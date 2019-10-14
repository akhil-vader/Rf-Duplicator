#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: akhil

This code reads an input file of json objects containing certificate logs and finds duplicates based
on fingerprints. The code maintains a hashmap of duplicate json object positions in the input file.
This might lead to scalability issues as the number of unique fingerprints and duplicates increases

"""
import ijson
import io
import datetime
import os
import shutil

# File Constants
# Input

INPUT_FILE = 'ctl_records_sample.jsonlines'

# Output
OUTPUT_DIRECTORY = "output"
JSONLINE_EXTENSION = '.jsonline'


def print_to_console(message):
    print(message)


def clean_and_create_directory(directory):
    if not os.path.exists(directory):
        os.mkdir(directory)
    else:
        shutil.rmtree(directory)
        os.mkdir(directory)


def get_file_path(directory, filename, extension=""):
    return directory + "/" + filename + extension


class MapValue(object):
    """
    The values in the fingerprint hashmap are of this class type. This object is used to aid in the process of
    identifying duplicates in the input file
    """

    __slots__ = ['position_array']

    def __init__(self, position_array):
        """
        Constructor for the map value class
        :param position_array: maintains an array of (start, length) tuple which
        indicates the start offset of the json object and length of it
        """

        self.position_array = position_array


class CertificateDuplicateIdentifier(object):
    def __init__(self):
        self.input_file = ""
        self.output_file = "duplicate_certificates"
        self.output_directory = "output"

        self.finger_print_map = {}

    def process_data(self, input_file):
        """
        This method reads through the input, identifies duplicate json objects, populates fingerprint hashmap
        with position offset of each duplicate in the input file
        :param input_file: Input jsonlines file
        """

        # Validate input and define paths
        if not os.path.exists(input_file):
            raise Exception('Input file does not exists')

        self.input_file = input_file

        start_time = datetime.datetime.now()

        print_to_console("Data processing started at: {0}".format(start_time))

        # Process input
        with open(self.input_file, mode='rb') as input_file_fp:
            start = input_file_fp.tell()
            line = input_file_fp.readline()
            while line:
                # While loop that reads input line by line until end of the file

                end = input_file_fp.tell()

                # Retrieve fingerprint from the json object using ijson (avoids using json loads for faster execution)
                finger_print_str = list(ijson.items(io.BytesIO(line), 'data.leaf_cert'))[0]['fingerprint']

                # Length of the json object
                length = end - start

                # Checks if fingerprint has already been seen or not
                if finger_print_str in self.finger_print_map:
                    map_value = self.finger_print_map[finger_print_str]
                    map_value.position_array.append((start, length))
                    self.finger_print_map[finger_print_str] = map_value

                else:
                    map_value = MapValue([(start, length)])
                    self.finger_print_map[finger_print_str] = map_value

                # Offset before reading the next line
                start = input_file_fp.tell()
                line = input_file_fp.readline()

        print_to_console("Data processed in: {0}".format(datetime.datetime.now() - start_time))

    def write(self, output_directory="", output_file=""):
        """
        This method reads through the hashmap, identifies fingerprints that has duplicates
        and finally writes down the duplicates for each fingerprint
        :param output_directory: Specific output location
        :param output_file: Output filename
        """

        start_time = datetime.datetime.now()
        print_to_console("Data writing started at: {0}".format(start_time))

        # Validate input
        if not os.path.exists(self.input_file):
            raise Exception('Input file does not exists')

        if not output_directory:
            output_directory = self.output_directory
        # Clean output
        clean_and_create_directory(output_directory)

        # Define paths
        self.output_file = get_file_path(output_directory, self.output_file, JSONLINE_EXTENSION)

        # Loop through the hashmap and write the duplicates in desired format
        with open(self.output_file, 'w') as outfile:
            for finger_print_str, map_val in self.finger_print_map.items():

                # Condition checks if duplicate exists for the fingerprint
                if len(map_val.position_array) > 1:
                    text = '{"fingerprint": "%s", "certificates": [' % finger_print_str
                    for position in map_val.position_array:
                        start = position[0]
                        length = position[1]
                        with open(self.input_file, 'r') as input_file_fp:
                            input_file_fp.seek(start)
                            line = input_file_fp.read(length)
                        text += line.rstrip() + ','
                    text = text.rstrip(',') + ']}' + '\n'
                    outfile.write(text)
        print("Data writing completed  in: {0}".format(datetime.datetime.now() - start_time))


if __name__ == '__main__':
    cert_dupl_identifier = CertificateDuplicateIdentifier()
    cert_dupl_identifier.process_data(INPUT_FILE)
    cert_dupl_identifier.write(OUTPUT_DIRECTORY)
