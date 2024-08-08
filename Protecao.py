import bcrypt
import jwt
import datetime
from cryptography.fernet import Fernet
from scapy.all import sniff

class SecuritySystem:
    def __init__(self, secret_key):
        self.secret_key = secret_key

    # Criptografia de Dados
    def generate_key(self):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)

    def load_key(self):
        return open("secret.key", "rb").read()

    def encrypt_message(self, message: str):
        key = self.load_key()
        f = Fernet(key)
        encrypted_message = f.encrypt(message.encode())
        return encrypted_message

    def decrypt_message(self, encrypted_message: bytes):
        key = self.load_key()
        f = Fernet(key)
        decrypted_message = f.decrypt(encrypted_message)
        return decrypted_message.decode()

    # Autenticação Segura
    def hash_password(self, password: str):
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode(), salt)
        return hashed

    def check_password(self, password: str, hashed: bytes):
        return bcrypt.checkpw(password.encode(), hashed)

    def generate_token(self, user_id: str):
        payload = {
            "user_id": user_id,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }
        token = jwt.encode(payload, self.secret_key, algorithm="HS256")
        return token

    def verify_token(self, token: str):
        try:
            decoded = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            return decoded
        except jwt.ExpiredSignatureError:
            return None

    # Detecção de Intrusões
    def packet_callback(self, packet):
        if packet.haslayer("TCP"):
            if packet["TCP"].flags == "S":
                print(f"Syn Scan Detectado: {packet.summary()}")

    def start_sniffing(self, interface: str):
        print(f"Começando a capturar na interface {interface}")
        sniff(iface=interface, prn=self.packet_callback, store=0)

# Interface Simples para Interagir com o Sistema
def main():
    secret_key = "chave_secreta"  # Deve ser uma chave segura e secreta
    security_system = SecuritySystem(secret_key)

    while True:
        print("\nSistema de Segurança")
        print("1. Gerar chave de criptografia")
        print("2. Criptografar mensagem")
        print("3. Descriptografar mensagem")
        print("4. Hash de senha")
        print("5. Verificar senha")
        print("6. Gerar token JWT")
        print("7. Verificar token JWT")
        print("8. Iniciar detecção de intrusões")
        print("9. Sair")
        choice = input("Escolha uma opção: ")

        if choice == "1":
            security_system.generate_key()
            print("Chave de criptografia gerada e salva.")
        elif choice == "2":
            message = input("Digite a mensagem para criptografar: ")
            encrypted_message = security_system.encrypt_message(message)
            print(f"Mensagem Criptografada: {encrypted_message}")
        elif choice == "3":
            encrypted_message = input("Digite a mensagem criptografada: ").encode()
            decrypted_message = security_system.decrypt_message(encrypted_message)
            print(f"Mensagem Descriptografada: {decrypted_message}")
        elif choice == "4":
            password = input("Digite a senha para hash: ")
            hashed_password = security_system.hash_password(password)
            print(f"Senha Hash: {hashed_password}")
        elif choice == "5":
            password = input("Digite a senha: ")
            hashed_password = input("Digite o hash da senha: ").encode()
            if security_system.check_password(password, hashed_password):
                print("Senha verificada com sucesso.")
            else:
                print("Senha incorreta.")
        elif choice == "6":
            user_id = input("Digite o ID do usuário: ")
            token = security_system.generate_token(user_id)
            print(f"Token JWT: {token}")
        elif choice == "7":
            token = input("Digite o token JWT: ")
            decoded = security_system.verify_token(token)
            if decoded:
                print(f"Token verificado: {decoded}")
            else:
                print("Token inválido ou expirado.")
        elif choice == "8":
            interface = input("Digite a interface de rede para monitorar (e.g., eth0): ")
            security_system.start_sniffing(interface)
        elif choice == "9":
            break
        else:
            print("Opção inválida. Tente novamente.")

if __name__ == "__main__":
    main()
