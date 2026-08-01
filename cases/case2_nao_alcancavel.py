def vulnerable_function(user_input):
    return eval(user_input)


def helper():
    return "Operação segura"


def process_request():
    return helper()


def main():
    process_request()


main()