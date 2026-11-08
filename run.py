from app import create_app

if __name__ == "__main__":
    print("Laboratório intencionalmente vulnerável. Escutando só em 127.0.0.1.")
    # host fixo em loopback de propósito: não existe opção para expor na rede
    create_app().run(host="127.0.0.1", port=5001, debug=False)
