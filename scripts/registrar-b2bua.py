import sys
import KSR as KSR

# =========================================================
# CONFIGURAÇÃO E BASE DE DADOS
# =========================================================

# Base de dados em memória
redial_lists = {}

# Constantes
OPERATOR_DOMAIN = "acme.operador"
MAX_RETRIES = 3      
TEST_TIMEOUT = 5000  # 5 segundos para testes

# =========================================================
# HELPERS
# =========================================================

def get_aor_from_from():
    return "sip:%s@%s" % (KSR.pv.get("$fU"), KSR.pv.get("$fd"))

def check_domain_security():
    src_domain = KSR.pv.get("$fd")
    if src_domain != OPERATOR_DOMAIN:
        KSR.info(f"[SECURITY] Access Denied for domain: {src_domain}\n")
        KSR.sl.send_reply(403, "Forbidden - Service restricted to acme.operador")
        return False
    return True

# =========================================================
# KAMAILIO INITIALIZATION
# =========================================================

def mod_init():
    KSR.info("===== python mod_init() loaded for Redial 2.0 =====")
    return kamailio()

class kamailio:

    def __init__(self):
        KSR.info("===== kamailio.__init__ =====\n")

    def child_init(self, rank):
        return 0

    # ---------------------------------------------------------
    # LÓGICA CORE: Tenta o próximo destino (Redial)
    # ---------------------------------------------------------
    def try_next_redial_target(self):
        targets_str = KSR.pv.get("$avp(redial_targets)")
        current_idx = int(KSR.pv.get("$avp(current_idx)") or 0)
        retries = int(KSR.pv.get("$avp(retries)") or 0)

        if not targets_str:
            KSR.info("[REDIAL-STOP] No targets list found.\n")
            return 1 

        targets = targets_str.split(",")
        num_targets = len(targets)

        # Se ainda temos tentativas e a lista não está vazia
        if retries > 0 and num_targets > 0:
            
            # Loop na lista
            real_index = current_idx % num_targets
            target = targets[real_index]
            
            KSR.info(f"[REDIAL-STEP] Retry {retries} left. Next target is {target} (Index {real_index})\n")

            # 1. Define o novo Request-URI (AoR)
            KSR.pv.sets("$ru", target)
            
            # 2. ATENÇÃO: Faz o Lookup para descobrir o IP do destino!
            # Sem isto, o t_relay falha com "t_forward_noack"
            if KSR.registrar.lookup("location") != 1:
                KSR.info(f"[REDIAL-ERROR] Target {target} is OFFLINE/Not Registered. Skipping...\n")
                
                # Se este utilizador falhar (offline), tentamos logo o próximo recursivamente
                # Atualizamos indices antes de chamar de novo
                KSR.pv.sets("$avp(current_idx)", str(current_idx + 1))
                # Não decrementamos retries aqui para não queimar tentativas com offline (opcional)
                # Mas para simplificar, vamos deixar falhar e o loop continua na proxima iteração se quiseres
                # Ou forçamos o próximo passo:
                return self.try_next_redial_target()

            # 3. Atualiza estado para a próxima iteração
            KSR.pv.sets("$avp(current_idx)", str(current_idx + 1))
            KSR.pv.sets("$avp(retries)", str(retries - 1))

            # 4. Re-arma a failure route e timer
            KSR.tm.t_on_failure("ksr_failure_route_REDIAL_FAILURE")
            KSR.tm.t_set_fr(TEST_TIMEOUT, TEST_TIMEOUT) 
            
            # 5. Envia
            KSR.tm.t_relay()
            return 1
        
        KSR.info("[REDIAL-STOP] Retries exhausted.\n")
        KSR.sl.send_reply(480, "Redial Failed - Given Up")
        return 1

    # =====================================================
    # REQUEST ROUTE
    # =====================================================
    def ksr_request_route(self, msg):
        global redial_lists

        if not check_domain_security():
            return 1

        # REGISTER
        if KSR.is_method("REGISTER"):
            sender = get_aor_from_from()
            expires_hdr = KSR.pv.get("$hdr(Expires)")
            contact_expires = KSR.pv.get("$(ct{param.value,expires})") 
            
            exp_val = 3600
            if expires_hdr is not None:
                exp_val = int(expires_hdr)
            elif contact_expires is not None:
                exp_val = int(contact_expires)

            if exp_val == 0:
                if sender in redial_lists:
                    del redial_lists[sender]
                KSR.registrar.save("location", 0)
                return 1

            if sender not in redial_lists:
                redial_lists[sender] = []
            
            KSR.registrar.save("location", 0)
            return 1

        # MESSAGE (ACTIVATE/DEACTIVATE)
        if KSR.is_method("MESSAGE"):
            if KSR.pv.get("$rU") == "redial" and KSR.pv.get("$rd") == OPERATOR_DOMAIN:
                body = str(KSR.pv.get("$rb")).strip()
                sender = get_aor_from_from()

                if sender not in redial_lists:
                    KSR.sl.send_reply(403, "User not registered")
                    return 1

                if body.startswith("ACTIVATE"):
                    parts = body.split()[1:] 
                    if parts:
                        clean_targets = []
                        for u in parts:
                            u = u.strip()
                            if u.startswith("sip:"): u = u[4:]
                            if "@" not in u: u = f"{u}@{OPERATOR_DOMAIN}"
                            clean_targets.append(f"sip:{u}")
                        
                        redial_lists[sender] = clean_targets
                        KSR.info(f"[REDIAL-CFG] Activated for {sender}. List: {clean_targets}\n")
                        KSR.sl.send_reply(200, "OK - Service Activated")
                        return 1

                if body.startswith("DEACTIVATE"):
                    redial_lists[sender] = [] 
                    KSR.sl.send_reply(200, "OK - Service Deactivated")
                    return 1
                
                KSR.sl.send_reply(400, "Unknown Command")
                return 1

        # INVITE
        if KSR.is_method("INVITE"):
            sender = get_aor_from_from()
            original_target = KSR.pv.get("$tu")
            active_list = redial_lists.get(sender, [])
            
            if active_list and original_target in active_list:
                KSR.info(f"[REDIAL-START] Watch list match for {original_target}. Monitoring.\n")
                
                KSR.pv.sets("$avp(retries)", str(MAX_RETRIES))
                KSR.pv.sets("$avp(redial_targets)", ",".join(active_list))
                KSR.pv.sets("$avp(current_idx)", "0") 

                KSR.tm.t_on_failure("ksr_failure_route_REDIAL_FAILURE")
                
                if KSR.tm.t_set_fr(TEST_TIMEOUT, TEST_TIMEOUT) < 0:
                     KSR.info("[REDIAL-WARN] Error setting timer\n")

                if KSR.registrar.lookup("location") == 1:
                    KSR.tm.t_relay()
                else:
                    return self.try_next_redial_target()
                
                return 1

            if KSR.registrar.lookup("location") == 1:
                KSR.tm.t_relay()
                return 1
            
            KSR.sl.send_reply(404, "User Not Found")
            return 1

        if KSR.is_method("ACK") or KSR.is_method("BYE") or KSR.is_method("CANCEL"):
            KSR.rr.loose_route()
            if KSR.is_method("BYE") or KSR.is_method("CANCEL"):
                 if KSR.registrar.lookup("location") == 1:
                    KSR.tm.t_relay()
            else:
                KSR.tm.t_relay()
            return 1
            
        return 1

    # =====================================================
    # FAILURE ROUTE
    # =====================================================
    def ksr_failure_route_REDIAL_FAILURE(self, msg):
        status = int(KSR.pv.get("$rs") or 0)
        
        KSR.info(f"[REDIAL-FAIL-DEBUG] Call failed with Code: {status}\n")

        # Inclui status 0 (timeout local)
        if status == 486 or status == 408 or status == 480 or status == 0:
            KSR.info(f"[REDIAL-ACTION] Triggering retry logic.\n")
            return self.try_next_redial_target()
        
        return 1