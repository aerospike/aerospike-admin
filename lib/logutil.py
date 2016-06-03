import os

__author__ = 'aerospike'

DATE_SEG = 0
DATE_SEPARATOR = "-"
TIME_SEG = 1
TIME_SEPARATOR = ":"

def check_time(val, date_string, segment, index=""):
        try:
            if segment == DATE_SEG:
                if val.__contains__("-"):
                    for v in range(
                            int(val.split("-")[0]), int(val.split("-")[1]) + 1):
                        if int(date_string.split(" ")[DATE_SEG].split(DATE_SEPARATOR)[index]) == v:
                            return True

                elif val.__contains__(","):
                    for v in val.split(","):
                        if int(date_string.split(" ")[DATE_SEG].split(DATE_SEPARATOR)[index]) == int(v):
                            return True

                else:
                    if int(date_string.split(" ")[DATE_SEG].split(DATE_SEPARATOR)[index]) == int(val):
                        return True
            elif segment == TIME_SEG:
                if val.__contains__("-"):
                    for v in range(
                            int(val.split("-")[0]), int(val.split("-")[1]) + 1):
                        if int(date_string.split(" ")[TIME_SEG].split(TIME_SEPARATOR)[index]) == v:
                            return True

                elif val.__contains__(","):
                    for v in val.split(","):
                        if int(date_string.split(" ")[TIME_SEG].split(TIME_SEPARATOR)[index]) == int(v):
                            return True

                else:
                    if int(date_string.split(" ")[TIME_SEG].split(TIME_SEPARATOR)[index]) == int(val):
                        return True
        except Exception:
            pass

        return False

def get_dirs(path=""):
        try:
            return [name for name in os.listdir(path)
                    if os.path.isdir(os.path.join(path, name))]
        except Exception:
            return []

def get_all_files(dir_path=""):
        file_list = []
        if not dir_path:
            return file_list
        try:
            for root,sub_dir,files in os.walk(dir_path):
                for file in files:
                    file_list.append(os.path.join(root, file))
        except Exception:
            pass

        return file_list

def intersect_list(a, b):
        return list(set(a) & set(b))

def fetch_value_from_dic(hash, keys):
        if not hash or not keys:
            return "N/E"
        temp_hash = hash
        for key in keys:
            if key in temp_hash:
                temp_hash = temp_hash[key]
            else:
                return "N/E"
        return temp_hash
