import sys
import KSR as KSR

# --- Variaveis globais ---
redial_lists = {}
OPERATOR_DOMAIN = "acme.operador"
PIN_DOMAIN = "acme.pt"
MAX_RETRIES = 2      
TEST_TIMEOUT = 36000  



def get_aor():
    return f"sip:{KSR.pv.get('$fU')}@{KSR.pv.get('$fd')}"



# --- Verifica o Dominio ---
def check_domain():
    if KSR.pv.get("$fd") != OPERATOR_DOMAIN:
        KSR.info(f"[SEC] Denied: {KSR.pv.get('$fd')}\n")
        KSR.sl.send_reply(403, "Forbidden - acme.operador only")
        return False
    return True



def mod_init():
    return kamailio()



class kamailio:
    def child_init(self, rank): return 0

    # --- REDIAL ---
    def try_next_redial(self):
        # Le o estado
        targets = (KSR.pv.get("$avp(redial_targets)") or "").split(",")
        idx = int(KSR.pv.get("$avp(current_idx)") or 0)
        retries = int(KSR.pv.get("$avp(retries)") or 0)

        if not targets or not targets[0] or retries <= 0:
            KSR.info("[REDIAL] Stop: No retries or empty list.\n")
            KSR.sl.send_reply(480, "Redial Given Up")
            return 1

        # Selecionar a quem fazer redial
        target = targets[idx % len(targets)]
        KSR.info(f"[REDIAL] Retry {retries} left. Target: {target}\n")

        # Configurar envio
        KSR.pv.sets("$ru", target)
        KSR.pv.sets("$avp(current_idx)", str(idx + 1))
        
        # Verificar se está registado
        if KSR.registrar.lookup("location") != 1:
            KSR.info(f"[REDIAL] {target} Offline. Skipping...\n")
            return self.try_next_redial() # Recursão para o próximo

        # Preparar falha e enviar
        KSR.pv.sets("$avp(retries)", str(retries - 1))
        KSR.tm.t_on_failure("failure_REDIAL")
        KSR.tm.t_set_fr(TEST_TIMEOUT, TEST_TIMEOUT)
        KSR.tm.t_relay()
        return 1

    # --- ROUTING DE PEDIDOS ---
    def ksr_request_route(self, msg):
        # Verificação de dominio
        if not check_domain(): return 1

        sender = get_aor()

        # --- REGISTO ---
        if KSR.is_method("REGISTER"):
            # Obter expires 
            exp = int(KSR.pv.get("$hdr(Expires)") or KSR.pv.get("$(ct{param.value,expires})") or 3600)
            
            if exp == 0:
                redial_lists.pop(sender, None) 
                KSR.info(f"[REG] {sender} Deregistered.\n")
                KSR.sl.send_reply(200, "Deregistered")
            elif sender not in redial_lists:
                redial_lists[sender] = [] 
                KSR.info(f"[REG] {sender} Registered.\n")
                KSR.sl.send_reply(200, "Registered")
            
            KSR.registrar.save("location", 0)
            return 1

        # --- MESSAGE ---
        if KSR.is_method("MESSAGE"):
            body = str(KSR.pv.get("$rb")).strip()
            dest_user = KSR.pv.get("$rU")
            dest_domain = KSR.pv.get("$rd")

            # --- Verificação PIN ---
            if dest_user == "validar" and dest_domain == PIN_DOMAIN:
                
                if body == "0000":
                    if sender not in redial_lists:
                        redial_lists[sender] = []
                    
                    KSR.info(f"[PIN] User {sender} validated with PIN.\n")
                    KSR.sl.send_reply(200, "PIN OK - Registered")
                    return 1
                else:
                    KSR.info(f"[PIN] User {sender} failed validation. Wrong PIN: {body}\n")
                    KSR.sl.send_reply(403, "Invalid PIN")
                    return 1

            # --- Activate/Deactivate serviço Redial 2.0 ---
            if dest_user == "redial":
                if sender not in redial_lists:
                    KSR.sl.send_reply(403, "Not Registered")
                    return 1

                # --- Ativação do Redial 2.0 ---
                if body.startswith("ACTIVATE"):
                    parts = body.split()[1:] 
                    clean_list = []

                    for user in parts:
                        user = user.strip()
                        if user.startswith("sip:"):
                            user = user.replace("sip:", "")

                        clean_list.append("sip:" + user)

                    redial_lists[sender] = clean_list
                    KSR.sl.send_reply(200, f"Activated: {clean_list}")
                    return 1

                # --- Desativação do Redial 2.0 ---
                if body.startswith("DEACTIVATE"):
                    redial_lists[sender] = []
                    KSR.sl.send_reply(200, "Deactivated")
                    return 1

                KSR.sl.send_reply(400, "Unknown Command")
                return 1

        # --- INVITE ---
        if KSR.is_method("INVITE"):
            target = KSR.pv.get("$tu")
            watchlist = redial_lists.get(sender, [])

            # --- REDIAL 2.0 ---
            if watchlist and target in watchlist:
                KSR.info(f"[REDIAL] Monitoring call to {target}\n")
                KSR.pv.sets("$avp(retries)", str(MAX_RETRIES))
                KSR.pv.sets("$avp(redial_targets)", ",".join(watchlist))
                KSR.pv.sets("$avp(current_idx)", "0")
                
                KSR.tm.t_on_failure("failure_REDIAL")
                KSR.tm.t_set_fr(TEST_TIMEOUT, TEST_TIMEOUT)

                if KSR.registrar.lookup("location") != 1:
                     return self.try_next_redial() 

                KSR.tm.t_relay()
                return 1

            # --- Chamada Básica ---
            if KSR.registrar.lookup("location") == 1:
                KSR.tm.t_relay()
            else:
                KSR.sl.send_reply(404, "Not Found")
            return 1

        if KSR.is_method("ACK"):
            KSR.info("ACK R-URI: " + KSR.pv.get("$ru") + "\n")
            KSR.rr.loose_route()  # In case there are Record-Route headers
            KSR.registrar.lookup("location")
            KSR.tm.t_relay()
            return 1

        if KSR.is_method("BYE"):
            KSR.info("BYE R-URI: " + KSR.pv.get("$ru") + "\n")
            KSR.rr.loose_route()    # In case there are Record-Route headers
            KSR.registrar.lookup("location")
            KSR.tm.t_relay()
            return 1

        if KSR.is_method("CANCEL"):
            KSR.info("CANCEL R-URI: " + KSR.pv.get("$ru") + "\n")
            KSR.rr.loose_route()    # In case there are Record-Route headers
            KSR.registrar.lookup("location")
            KSR.tm.t_relay()
            return 1

    # --- Reencaminhamento do redial ---
    def failure_REDIAL(self, msg):
        status = int(KSR.pv.get("$rs") or 0)
        # 0=Local Timeout/Err, 408=Timeout, 480=Unavailable, 486=Busy
        if status in [0, 408, 480, 486]:
            KSR.info(f"[FAIL] Status {status}. Redialing...\n")
            return self.try_next_redial()
        return 1