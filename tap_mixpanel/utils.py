import re


def convert_to_snakecase(string):
    return re.sub(r'\W+', '_', string).lower()
