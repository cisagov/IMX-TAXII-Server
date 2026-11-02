import json
import random
import string

def generate_random_string(length):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string

def generate_random_number(length):
    nums = string.digits
    return random.randint(1, length)

def read_json_data_from_file(filename):
	with open(filename, 'r') as f:
		data = json.load(f)
	return data
