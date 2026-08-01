def vulnerable_function(user_input):
    return eval(user_input)


def parse_request(user_input):
    return vulnerable_function(user_input)


def process_request(user_input):
    return parse_request(user_input)


def main():
    user_input = input("Entrada: ")
    process_request(user_input)


main()


# # vulnerable.py
# def vulnerable():
#     print("Entrou na função vulnerável")

# def helper():
#     pass

# def process():
#     helper()

# def main():
#     process()

# main()