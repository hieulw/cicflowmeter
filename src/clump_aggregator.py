#!/usr/bin/env python3

import argparse
import json
import os

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('input_dir')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--json', dest='file_type', action='store_const', const='json')
    group.add_argument('--csv', dest='file_type', action='store_const', const='csv')
    args = parser.parse_args()
    path = args.input_dir
    file_type = args.file_type
    files = [os.path.join(path, f) for f in os.listdir(path) if
             f.endswith(".{}".format(file_type)) and not f == 'all.{}'.format(file_type)]

    if file_type == 'json':
        out = open(os.path.join(path, 'all.json'), 'w')
        contents = list()
        out.write('[\n')
        for file_num, file_path in enumerate(files):
            try:
                print('[{}/{}] {}'.format(file_num, len(files), file_path))
                f = open(file_path, 'r')
                f_c = json.load(f)
                if file_num != 0:
                    out.write(',\n')
                out.write(',\n'.join(json.dumps(obj) for obj in f_c))
                f.close()
            except json.JSONDecodeError:
                print('ERROR')

        out.write(']\n')
        out.close()
    else:
        out = open(os.path.join(path, 'all.csv'), 'w')
        contents = list()
        for file_num, file_path in enumerate(files):
            f = open(file_path, 'r')
            for line_num, line in enumerate(f):
                if line_num == 0 and file_num != 0:
                    continue
                contents.append(line)
            print(file_num, file_path)
        out.writelines(contents)
        out.close()

