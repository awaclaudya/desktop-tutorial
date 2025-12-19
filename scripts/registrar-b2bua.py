import sys
import KSR as KSR

# =========================================================
# Global state (NOTE: em produção usar htable/redis/usrloc)
# =========================================================
redial_lists = {}

# =========================================================
# Helpers
# =========================================================

def get_aor_from_from():
    """Retorna AOR limpo a partir do From (sem tag)."""
    return "sip:%s@%s" % (KSR.pv.get("$fU"), KSR.pv.get("$fd"))

# =========================================================
# Mandatory module init
# =========================================================

def mod_init():
    KSR.info("===== python mod_init() loaded =====")
    # MODO CLASS-BASED: é OBRIGATÓRIO devolver a instância da classe
    return kamailio()

# =========================================================
# Kamailio main class
# =========================================================

class kamailio:

    def __init__(self):
        KSR.info("===== kamailio.__init__ =====\n")

    def child_init(self, rank):
        KSR.info(f"===== kamailio.child_init({rank}) =====\n")
        return 0

    # =====================================================
    # REQUEST ROUTE
    # =====================================================
    def ksr_request_route(self, msg):
        global redial_lists

        # ---------------- MESSAGE ----------------
        if KSR.is_method("MESSAGE"):
            r_user = KSR.pv.get("$rU")
            r_domain = KSR.pv.get("$rd")

            # --- REDIAL CONTROL SERVICE ---
            if r_user == "redial" and r_domain == "acme.operador":
                body = KSR.pv.get("$rb")
                if body is None:
                    KSR.sl.send_reply(400, "Missing Body")
                    return 1

                message = str(body).strip()
                sender = get_aor_from_from()

                if message.startswith("ACTIVATE"):
                    parts = message.split()[1:]
                    if not parts:
                        KSR.sl.send_reply(400, "No targets")
                        return 1

                    targets = []
                    for u in parts:
                        if u.lower().startswith("sip:"):
                            targets.append(u)
                        else:
                            targets.append("sip:" + u)

                    redial_lists[sender] = targets
                    KSR.info(f"REDIAL LIST for {sender}: {targets}\n")
                    KSR.sl.send_reply(200, "OK - Redial Activated")
                    return 1

                KSR.sl.send_reply(400, "Unknown Command")
                return 1

            # --- NORMAL CHAT (local only) ---
            if KSR.pv.get("$td") == "acme.operador":
                if KSR.registrar.lookup("location") == 1:
                    KSR.tm.t_relay()
                    return 1
                else:
                    KSR.sl.send_reply(404, "User Not Found")
                    return 1

            KSR.sl.send_reply(403, "Forbidden")
            return 1

        # ---------------- REGISTER ----------------
        if KSR.is_method("REGISTER"):
            domain = KSR.pv.get("$td")
            aor = KSR.pv.get("$tu")

            if domain != "acme.operador":
                KSR.sl.send_reply(403, "Forbidden Domain")
                return 1

            expires = KSR.hdr.get("Expires")
            if expires is None:
                contact = KSR.pv.get("$ct")
                if contact and "expires=0" in contact.lower():
                    expires = "0"

            # De-register
            if expires == "0":
                if aor in redial_lists:
                    del redial_lists[aor]
                    KSR.info(f"REDIAL LIST removed for {aor}\n")

                KSR.registrar.save("location", 0)
                return 1

            # Register
            redial_lists.setdefault(aor, [])
            KSR.info(f"REGISTER {aor}, redial list initialized\n")
            KSR.registrar.save("location", 0)
            return 1

        # ---------------- INVITE ----------------
        if KSR.is_method("INVITE"):
            sender = get_aor_from_from()
            target = KSR.pv.get("$tu")

            is_redial = False

            if KSR.pv.get("$rU") == "redial" and KSR.pv.get("$rd") == "acme.operador":
                is_redial = True
            elif sender in redial_lists and target in redial_lists[sender]:
                is_redial = True

            if is_redial:
                targets = redial_lists.get(sender, [])
                if not targets:
                    KSR.sl.send_reply(404, "Redial list empty")
                    return 1

                KSR.pv.sets("$avp(retries)", "2")
                KSR.pv.sets("$avp(redial_targets)", ",".join(targets))
                KSR.tm.t_on_failure("ksr_failure_route_REDIAL_FAILURE")

                KSR.pv.sets("$ru", targets[0])
                if KSR.registrar.lookup("location") != 1:
                    KSR.sl.send_reply(404, "User Offline")
                    return 1

                KSR.tm.t_relay()
                return 1

            # Normal call
            if KSR.pv.get("$td") != "acme.operador":
                KSR.sl.send_reply(403, "Forbidden")
                return 1

            if KSR.registrar.lookup("location") == 1:
                KSR.tm.t_relay()
                return 1

            KSR.sl.send_reply(404, "Not Found")
            return 1

        # ---------------- ACK / BYE / CANCEL ----------------
        if KSR.is_method("ACK") or KSR.is_method("BYE") or KSR.is_method("CANCEL"):
            KSR.rr.loose_route()
            KSR.registrar.lookup("location")
            KSR.tm.t_relay()
            return 1
        KSR.sl.send_reply(403, "Forbidden method")
        return 1


    # =====================================================
    # FAILURE ROUTE
    # =====================================================
    def ksr_failure_route_REDIAL_FAILURE(self, msg):
        # 1. Get the Reply Status ($rs)
        # If the call times out (no reply), $rs is null/None. We convert that to 0.
        code_str = KSR.pv.get("$rs")
        code = int(code_str) if code_str else 0
        
        # 2. Get current retries count
        retries_str = KSR.pv.get("$avp(retries)")
        retries = int(retries_str) if retries_str else 0

        KSR.info(f"FAILURE ROUTE triggered. Code: {code}, Retries left: {retries}\n")

        # 3. Check for Failure Codes
        # We must include '0' to catch Timeouts (when the phone just rings with no answer)
        # 408 = Request Timeout (generated internally or received)
        # 480 = Temporarily Unavailable
        # 486 = Busy Here
        if (code == 0 or code in (408, 480, 486)) and retries > 0:
            targets_str = KSR.pv.get("$avp(redial_targets)")
            
            if targets_str:
                targets = targets_str.split(",")
                
                # DECREMENT RETRIES for the next attempt
                retries = retries - 1
                
                # Calculate the index for the next target
                # Example: 2 targets total.
                # Start: retries=2. 
                # 1st Failure: new retries=1. Index = 2 - 1 = 1 (Second target)
                idx = len(targets) - retries

                if idx < len(targets):
                    next_target = targets[idx]
                    KSR.info(f"REDIAL: Routing to next target: {next_target}\n")

                    # Set the new destination (Request-URI)
                    KSR.pv.sets("$ru", next_target)
                    
                    # Update retries AVP for the next loop
                    KSR.pv.sets("$avp(retries)", str(retries))
                    
                    # IMPORTANT: Re-arm the failure route! 
                    # Without this, if the 2nd call fails, the script won't run again.
                    KSR.tm.t_on_failure("ksr_failure_route_REDIAL_FAILURE")
                    
                    # Relay the new INVITE statefully
                    KSR.tm.t_relay()
                    return 1

        KSR.info("REDIAL: Stopped. No more retries or fatal error.\n")
        return 1