import csv
import os.path
from flask import Flask
app = Flask(__name__)


@app.route('/')
def hello():
    return "Hello World!"

@app.route('/phuzzer')
def phuzzer():

    deets_fn = os.path.join(os.getcwd(),"run_details.txt")

    if os.path.exists(deets_fn):
        return {'message': f"The file {deets_fn} does not exist"}, 500

    with open('employee_birthday.txt') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0

    return "Hello World!"


if __name__ == '__main__':
    app.run()