ALLOWED_COMMANDS = {
    "status": "Sistema operacional",
    "version": "1.0.0",
}


def vulnerable_function(command):
    return ALLOWED_COMMANDS[command]


def validate_command(command):
    if command not in ALLOWED_COMMANDS:
        raise ValueError("Comando não permitido")

    return command


def process_request(command):
    validated_command = validate_command(command)
    return vulnerable_function(validated_command)


def main():
    command = input("Comando: ")
    print(process_request(command))


main()