import os
import json

def parse(file_path):
    all_line = 0
    coverage_line = 0

    with open(file_path, 'r') as f:
        try:
            # JSON 파일을 파싱하여 데이터를 가져옴
            data = json.load(f)
            for key in data.keys():
                all_line += len(data[key])
                for _ in data[key].keys():
                    if data[key][_] == 1:
                        coverage_line += 1
        except json.JSONDecodeError as e:
            print(f"Error in Json decoding")

    return all_line , coverage_line

folder_path = '/tmp/coverage/'
file_list = os.listdir(folder_path)
json_files = [file for file in file_list if file.endswith('.json')]

for json_file in json_files:
    lines, coverage = parse(folder_path+json_file)
    print("Json_file : ", json_file )
    print("Coverage rate : ", str((coverage / lines * 100)) + "%")