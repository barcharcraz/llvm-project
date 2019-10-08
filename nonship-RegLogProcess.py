import argparse
import xlsxwriter
import re

parser = argparse.ArgumentParser(description='Process REGRESS run log data')
parser.add_argument('md_asan', help='path to md_asan results log')
parser.add_argument('md_without_asan', help='path to md_without_asan results log')
parser.add_argument('mt_asan', help='path to mt_asan results log')
parser.add_argument('mt_without_asan', help='path to mt_without_asan log')
parser.add_argument('failure_list', help='path to failure list')
parser.add_argument('ignore_list', help='path to ignore list')
args = parser.parse_args()

expected_failures_list = []
ignored_list = []

class RegressRun:
    def __init__(self):
        self.runs = {}

    def insert_run(self, dirname, filename, flags, status, x_status):
        # this function creates a dictionary of the format:
        # {dirname: {filename: {[(flags, status)]}}}
        if dirname in self.runs:
            if filename in self.runs[dirname]:
                self.runs.get(dirname).get(filename).append((flags, status, x_status))
            else:
                self.runs.get(dirname).update({filename:[(flags, status, x_status)]})
        else:
            self.runs.update({dirname:{filename:[(flags, status, x_status)]}})

def create_dict(file, dataset):
    global expected_failures_list
    global ignored_list
    with open(file, "r") as contents:
        for line in contents:
            x_status = "expected_pass"
            # scan through expected failures
            for prefix in expected_failures_list:
                if re.search(prefix, line):
                    x_status = "expected_failure"
            
            for prefix in ignored_list:
                if re.search(prefix, line):
                    x_status = "ignored"
            
            # parsing the data
            data = line.split()
            flags = data[2:-3]
            flags[0] = flags[0].strip("(")
            flags[-1] = flags[-1].strip(")")
            
            # populating the dictionary
            dataset.insert_run(data[0], data[1].strip("("), flags, data[-1], x_status)

def populate_sheet(dataset, workbook, worksheet):
    # colorize rows
    failure_fmt = workbook.add_format()
    success_fmt = workbook.add_format()
    xFailure_fmt = workbook.add_format()
    ignore_fmt = workbook.add_format()
    failure_fmt.set_bg_color("red")
    success_fmt.set_bg_color("green")
    xFailure_fmt.set_bg_color("orange")
    ignore_fmt.set_bg_color("black")

    # Start from the first cell. Rows and columns are zero indexed.
    row = 0
    col = 0
    worksheet.write(row, col, "DIRNAME")
    worksheet.write(row, col + 6, "FAILURE_COUNT")

    # Iterate over the data and write it out row by row.
    for dirname in (dataset.runs):
        failure_count = 0
        for filename in dataset.runs[dirname]:
            for variations in dataset.runs[dirname][filename]:
                col = 0
                worksheet.write(row, col, dirname)
                worksheet.write(row, col+1, filename)
                internal_failure_count = 0
                status = str(variations[1])
                expected_status = str(variations[2])
                expected_failure = status == "failed" and  expected_status == "expected_failure"
                unexpected_pass = status =="passed" and expected_status == "expected_failure"

                fmt = success_fmt
                if status == "failed":
                    fmt = failure_fmt
                    failure_count += 1
                    internal_failure_count +=1 
                if expected_failure:
                    fmt = xFailure_fmt
                    failure_count -= 1
                    internal_failure_count -=1 
                if unexpected_pass:
                    fmt = failure_fmt
                if expected_status == "ignored":
                    fmt = ignore_fmt
                    if status == "failed":
                        failure_count -= 1
                        internal_failure_count -=1

                worksheet.write(row, col + 2, dirname + " " + "(" + filename + " " + str(variations[0]) + ")", fmt)
                worksheet.write(row, col + 3, status, fmt)
                worksheet.write(row, col + 4, expected_status, fmt)
                row += 1
            worksheet.write(row, col + 5, internal_failure_count)  
        worksheet.write(row, col + 6, failure_count)

def generate_datasheet():
    workbook = xlsxwriter.Workbook('data-viz.xlsx')
    md_asan_sheet = workbook.add_worksheet("MD-ASAN")
    md_without_asan_sheet = workbook.add_worksheet("MD-WITHOUT-ASAN")
    mt_asan_sheet = workbook.add_worksheet("MT-ASAN")
    mt_without_asan_sheet = workbook.add_worksheet("MT-WITHOUT-ASAN")

    populate_sheet(md_asan, workbook, md_asan_sheet)
    populate_sheet(md_without_asan, workbook, md_without_asan_sheet)
    populate_sheet(mt_asan, workbook, mt_asan_sheet)
    populate_sheet(mt_without_asan, workbook, mt_without_asan_sheet)
    workbook.close()


if __name__ == "__main__":
    # Creating an instance for all four dictionaries
    md_asan = RegressRun()
    md_without_asan = RegressRun()
    mt_asan = RegressRun()
    mt_without_asan = RegressRun()

    with open(args.failure_list,"r") as failure_list:
        for line in failure_list:
            if line.strip() != "" and not line.startswith('#'):    #hack comment line and get rid of blanks
                expected_failures_list.append(line.strip())

    with open(args.ignore_list, "r") as ignore_list:
        for line in ignore_list:
            if line.strip() != "" and not line.startswith('#'):    #hack comment line and get rid of blanks
                ignored_list.append(line.strip())


    # Parsing the logs and populating the dictionaries
    create_dict(args.md_asan, md_asan)
    create_dict(args.md_without_asan, md_without_asan)
    create_dict(args.mt_asan, mt_asan)
    create_dict (args.mt_without_asan, mt_without_asan)
    
    # Generate an excel sheet for visualization
    generate_datasheet()
