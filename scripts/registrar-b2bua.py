import sys
import KSR as KSR

# --- ADICIONE ESTA LINHA AQUI ---
# Variável global para armazenar as listas. Tem de estar fora da classe!
redial_lists = {} 
# --------------------------------
# Mandatory function - module initiation
def mod_init():
    KSR.info("===== from Python mod init\n")
    return kamailio()

class kamailio:
    # Mandatory function - Kamailio class initiation
    def __init__(self):
        KSR.info('===== kamailio.__init__\n')

    # Mandatory function - Kamailio subprocesses
    def child_init(self, rank):
        KSR.info('===== kamailio.child_init(%d)\n' % rank)
        return 0

    # Function called for messages sent/transit
    def ksr_onsend_route(self, msg):
        # Comment out the logging to avoid errors with msg.Type
        # KSR.info("===== onsend route - from kamailio python script:")
        # KSR.info("   %s\n" %(msg.Type))
        return 1
        

    # Function called for REQUEST messages received 
    def ksr_request_route(self, msg):
        # Aceder à variável global
        global redial_lists
        # Handle Instant Messages (SIP MESSAGE)
        if KSR.is_method("MESSAGE"):
              # 1. SPECIAL CASE: PIN Validation Service
              # We must check this FIRST. If we relay this, it will timeout (408).
            r_user = KSR.pv.get("$rU")
            r_domain = KSR.pv.get("$rd")

            if (r_user == "redial" and r_domain == "acme.operador"):
                body = KSR.pv.get("$rb")
                if body is None:
                    KSR.sl.send_reply(400, "Missing PIN")
                    return 1

                message = str(body).strip()
                KSR.info("Message Received for Redial: " + message + "\n")
                # Lógica para o comando ACTIVATE
                if message.startswith("ACTIVATE"):
                    parts = message.split()
                    raw_targets = parts[1:]

                    if not raw_targets:
                        KSR.sl.send_reply(400, "Bad Request - No users provided")
                        return 1

                    # Identificar quem enviou a mensagem
                    sender = KSR.pv.get("$fu")
                    
                    # NOVA LÓGICA: Normalizar os endereços adicionando "sip:" se necessário
                    normalized_targets = []
                    for user in raw_targets:
                        if not user.lower().startswith("sip:"):
                            normalized_targets.append("sip:" + user)
                        else:
                            normalized_targets.append(user)

                    # Guardar a lista normalizada
                    redial_lists[sender] = normalized_targets

                    KSR.info("Redial list updated for " + sender + ": " + str(normalized_targets) + "\n")
                    KSR.sl.send_reply(200, "OK - List Activated")
                    return 1
                # (Opcional) Manter a lógica antiga "ACTIVE" se ainda for necessária, ou removê-la
                elif (message == "ACTIVE"):
                    # ... lógica existente ...
                    KSR.sl.send_reply(200, "OK - Active (Legacy)")
                    return 1
                else:
                    KSR.sl.send_reply(400, "Unknown Command")
                    return 1

            if (r_user == "validar" and r_domain == "acme.pt"):
                body = KSR.pv.get("$rb")
                if body is None:
                    KSR.sl.send_reply(400, "Missing PIN")
                    return 1
                pin = str(body).strip()
                KSR.info("PIN Received: " + pin + "\n")
                if (pin == "0000"):
                    # Obter o endereço de quem enviou (Bob)
                    user_to_register = KSR.pv.get("$fu")

                    KSR.info("PIN Valid. Registering user: " + user_to_register + "\n")
                    # SOLUÇÃO FINAL: Usar save_uri para forçar o registo do "From" ($fu)
                    # Isto ignora o cabeçalho "To" (validar) e regista diretamente o Bob.
                    # O "0" é a flag (0 = default/memory)
                    if KSR.registrar.save_uri("location", 0, user_to_register) < 0:
                        KSR.err("Failed to register user " + user_to_register + "\n")
                        KSR.sl.send_reply(500, "Server Error")
                        return 1

                    KSR.sl.send_reply(200, "OK - Registered via PIN")
                    return 1
                else:
                    KSR.sl.send_reply(403, "Forbidden - Wrong PIN")
                    return 1
              # 2. NORMAL CHAT: Relay between local users (Alice <-> Bob)
              # We only allow relaying if the domain is OUR domain (acme.operador)
            if (KSR.pv.get("$td") == "acme.operador"):
                if (KSR.registrar.lookup("location") == 1):
                    KSR.tm.t_relay()
                    return 1
                else:
                    KSR.sl.send_reply(404, "User Not Found")
                    return 1
            # 3. BLOCK EVERYTHING ELSE
            # If it's not the validation service AND not a local user, reject it.
            # Do NOT use t_relay() here, or you will get 408 Timeout.
            KSR.sl.send_reply(403, "Forbidden - Wrong destination")
            return 1

        # Working as a Registrar server
        if KSR.is_method("REGISTER"):
            domain = KSR.pv.get("$td")
            user_aor = KSR.pv.get("$tu") # Address of Record (ex: sip:alice@acme.operador)

            KSR.info("REGISTER R-URI: " + KSR.pv.get("$ru") + "\n")
            KSR.info("            To: " + user_aor + "\n")

            # Lógica de verificação de domínio
            if (domain == "acme.operador"):
                
                # --- Lógica de Deteção de Expires Melhorada ---
                expires = KSR.hdr.get("Expires")
                
                # Se não houver cabeçalho Expires, verificar dentro do Contact
                if expires is None:
                    contact = KSR.pv.get("$ct")
                    
                    if contact and "expires=0" in contact.lower():
                        expires = "0"

                # De-registo (Expires == 0)
                if expires == "0":
                    KSR.info("User De-registering: " + user_aor + ". Deleting redial list.\n")
                    # Se a lista existir, removê-la
                    if user_aor in redial_lists:
                        del redial_lists[user_aor]
                        KSR.info("User " + user_aor + " removed from redial list.\n")
                    
                    # PROCESS DE-REGISTRATION AND EXIT
                    KSR.registrar.save('location', 0)
                    return 1
                        
                else:
                    KSR.info("User Registering: " + user_aor + ". Creating empty redial list.\n")
                    # Registo implica criação de lista vazia
                    redial_lists[user_aor] = []
                    KSR.info("redial list" + str(redial_lists[user_aor]) + "\n")

                    # Guardar a localização (fazer o registo efetivo no Kamailio)
                    KSR.registrar.save('location', 0)
                    return 1
            else:
                KSR.info("Domain check failed for: " + domain + "\n")
                KSR.sl.send_reply(403, "Forbidden Domain")
                return 1


        # Working as a Redirect/B2BUA server
        if KSR.is_method("INVITE"):                     
            KSR.info("INVITE R-URI: " + KSR.pv.get("$ru") + "\n")
            
            sender = KSR.pv.get("$fu")
            target_aor = KSR.pv.get("$tu")

            # --- LÓGICA REDIAL / RETRY ---
            is_redial_target = False
            
            # 1. Verifica se ligou para "redial"
            if KSR.pv.get("$rU") == "redial" and KSR.pv.get("$rd") == "acme.operador":
                is_redial_target = True
            
            # 2. Verifica se ligou para alguém da lista (ex: Alice)
            elif sender in redial_lists and target_aor in redial_lists[sender]:
                is_redial_target = True
                KSR.info("MATCH: User " + target_aor + " is in " + sender + "'s list. Activating Retry Logic.\n")

            if is_redial_target:
                if sender in redial_lists:
                    targets = redial_lists[sender]
                    if not targets:
                        KSR.sl.send_reply(404, "Redial List Empty")
                        return 1

                    # Vamos focar no primeiro destino da lista para o Retry
                    first_target = targets[0]
                    KSR.pv.sets("$ru", first_target)
                    
                    # --- CONFIGURAÇÃO DAS TENTATIVAS (RETRY) ---
                    # 1. Definimos que queremos 2 tentativas extra
                    KSR.pv.sets("$avp(retries)", "2")
                    
                    # 2. Armamos a Rota de Falha (tem de corresponder ao nome no app.cfg)
                    KSR.tm.t_on_failure("REDIAL_FAILURE")
                    
                    KSR.info("Starting Call with Retry Logic (2 retries)...\n")
                    
                    # 3. Fazemos o Lookup
                    if KSR.registrar.lookup("location") != 1:
                        KSR.sl.send_reply(404, "User Offline")
                        return 1

                    # 4. Envia
                    KSR.tm.t_relay()
                    return 1
                else:
                    KSR.sl.send_reply(404, "No Redial List Found")
                    return 1
            # ---------------------

            # Lógica Normal (para quem não está na lista)
            if (KSR.pv.get("$td") != "acme.operador"):       
                KSR.sl.send_reply(403, "Forbidden")
                return 1
            
            if (KSR.pv.get("$td") == "acme.operador"):             
                if (KSR.registrar.lookup("location") == 1):   
                    KSR.tm.t_relay()  
                    return 1
                else:
                    KSR.sl.send_reply(404, "Not found")
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
        # If this part is reached then Method is not allowed
        KSR.sl.send_reply(403, "Forbiden method")
        return 1






    # Function called for REPLY messages received
    def ksr_reply_route(self, msg):
        KSR.info("===== reply_route - from kamailio python script: ")
        KSR.info("  Status is:"+ str(KSR.pv.get("$rs")) + "\n")
        return 1




    # ---------------------------------------------------------
    # Rota de Falha: O nome TEM de ser ksr_failure_route_NOME
    # onde NOME é o que usou em t_on_failure("NOME")
    # ---------------------------------------------------------
    def ksr_failure_route_REDIAL_FAILURE(self, msg):
        code = KSR.pv.get("$rs") # Código do erro
        
        # 408=Timeout, 480=Unavailable, 486=Busy
        if code == 408 or code == 480 or code == 486:
            # Recupera o valor (pode vir como int ou str dependendo da versão)
            retries_val = KSR.pv.get("$avp(retries)")
            
            # Converter para inteiro para fazer a conta
            if retries_val is not None:
                retries = int(retries_val)
            else:
                retries = 0
            
            if retries > 0:
                KSR.info("Call Failed (" + str(code) + "). Retrying... Remaining: " + str(retries) + "\n")
                
                # Decrementa e converte para STRING antes de guardar
                next_try = str(retries - 1)
                KSR.pv.sets("$avp(retries)", next_try)
                
                # Prepara nova tentativa
                KSR.tm.t_on_failure("REDIAL_FAILURE") 
                KSR.tm.t_relay()
                return 1
            else:
                KSR.info("Call Failed. No more retries left.\n")
        
        return 1