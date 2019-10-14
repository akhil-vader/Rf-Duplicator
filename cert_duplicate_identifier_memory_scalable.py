#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: akhil

This code reads an input file of json objects containing certificate logs and finds duplicates based
on fingerprints. The code avoids loading objects into memory and thereby  maintaining a balance of
in-memory consumption and execution time.

"""

import datetime
import ijson
import io
import os
import shutil
import glob

# File Constants
# Input

INPUT_FILE = 'ctl_records_sample.jsonlines'

# Output
OUTPUT_DIRECTORY = "output"
JSONLINE_EXTENSION = '.jsonline'

# Constants
TAG_NEW = "NW"  # Tags the fingerprint when it is encountered for the first time
TAG_EXISTING = "EX"  # Tags the fingerprint as already seen


def print_to_console(message):
    print(message)


def get_file_path(directory, filename, extension=""):
    return directory + "/" + filename + extension


def clean_and_create_directory(directory):
    if not os.path.exists(directory):
        os.mkdir(directory)
    else:
        shutil.rmtree(directory)
        os.mkdir(directory)


def clean_directory(directory):
    if os.path.exists(directory):
        shutil.rmtree(directory)


class MapValue(object):
    """
    The values in the fingerprint hashmap are of this class type. This object is used to aid in the process of
    identifying duplicates in the input file
    """

    __slots__ = ['start', 'length', 'tag', 'path', 'end_offset']

    def __init__(self, start, length, tag, path, end_offset):
        """
        Constructor for the map value class
        :param start: Start offset of the json object line
        :param length: Length of the json object line
        :param tag: Tag indicating if fingerprint is new or seen
        :param path: Outuput filename of a fingerprint
        :param end_offset: End offset of a fingerprint in the output destination file
        """

        self.start = start
        self.length = length
        self.tag = tag
        self.path = path
        self.end_offset = end_offset


class CertificateDuplicateIdentifier(object):
    """
    The main class that identifies fingerprint duplicates in the given input file
    """

    def __init__(self):
        self.input_file = ""
        self.output_file = "duplicate_certificates"
        self.temp_directory = "temp"
        self.output_directory = "output"

        self.finger_print_map = {}

    def append(self, finger_print, map_val, current_obj):

        """
        Append method that writes the duplicate json objects for a corresponding fingerprint
        given that
        1) if it has already been written for this fingerprint
        2) else it is being written for the first time
        :param finger_print: fingerprint of certificate based on which the duplicates are identified
        :param map_val: hash map value for the input fingerprint
        :param current_obj: new json object being read for the fingerprint
        :return: returns the final position offset of a fingerprint output file
        """

        current_obj = current_obj.decode()
        finger_print_filename = map_val.path

        if map_val.tag == TAG_NEW:
            with open(self.input_file, mode='r') as temp_input_file_fp:

                # Read the first object from input
                temp_input_file_fp.seek(map_val.start)
                first_obj = temp_input_file_fp.read(map_val.length)

                # Creates text in the desired output format, uses string concatenation to
                # avoid usage of json loads and dumps
                temp_text = '{"fingerprint": "%s", "certificates": [' % finger_print

                # Creates an output file for a fingerprint when a duplicate has been identified for the first time
                with open(finger_print_filename, mode='w') as temp_fp:
                    temp_str = temp_text + first_obj.rstrip() + "," + current_obj.rstrip() + "]}" + "\n"
                    temp_fp.write(temp_str)
                    return temp_fp.tell()
        else:
            end = map_val.end_offset
            # Append a new duplicate json object to an existing fingerprint output file
            with open(finger_print_filename, mode='r+') as temp_input_file_fp:
                temp_input_file_fp.seek(end - 3)
                temp_input_file_fp.write(',' + current_obj.rstrip() + ']}' + "\n")
                return temp_input_file_fp.tell()

    def process_data(self, input_file, output_directory="", output_file=""):
        """
        This method reads through the input, identifies duplicate json objects, populates fingerprint hashmap,
        and finally writes down the duplicates for each fingerprint
        :param input_file: Input jsonlines file
        :param output_directory: Specific output location
        :param output_file: Output filename
        """

        # Validate input
        if not os.path.exists(input_file):
            raise Exception('Input file does not exists')

        if not output_directory:
            output_directory = self.output_directory
        # Clean output
        clean_and_create_directory(output_directory)

        self.temp_directory = output_directory + '/' + self.temp_directory

        # Clean and create temporary directory
        clean_and_create_directory(self.temp_directory)

        # Define the paths
        self.input_file = input_file
        self.output_file = get_file_path(output_directory, self.output_file, JSONLINE_EXTENSION)

        start_time = datetime.datetime.now()

        print_to_console("Data processing started at: {0}".format(start_time))

        # Process input
        with open(self.input_file, mode='rb') as input_file_fp:

            start = input_file_fp.tell()
            line = input_file_fp.readline()
            count = 0
            while line:
                # While loop that reads input line by line until end of the file

                end = input_file_fp.tell()

                # Retrieve fingerprint from the json object using ijson (avoids using json loads for faster execution)
                finger_print_str = list(ijson.items(io.BytesIO(line), 'data.leaf_cert'))[0]['fingerprint']

                # Length of the json object
                length = end - start

                if finger_print_str in self.finger_print_map:
                    map_value = self.finger_print_map[finger_print_str]

                    # Tag check to verify if fingerprint has already been seen or written to output
                    if map_value.tag == TAG_NEW:

                        # Number of unique fingerprints
                        count += 1
                        path = get_file_path(self.temp_directory, str(count), JSONLINE_EXTENSION)
                        map_value.path = path

                        end = self.append(finger_print_str, map_value, line)
                        map_value.end_offset = end
                        map_value.tag = TAG_EXISTING
                        self.finger_print_map[finger_print_str] = map_value
                    else:
                        end = self.append(finger_print_str, map_value, line)
                        map_value.end_offset = end
                        self.finger_print_map[finger_print_str] = map_value
                else:
                    map_value = MapValue(start, length, TAG_NEW, "", "")
                    self.finger_print_map[finger_print_str] = map_value

                # Offset before reading the next line
                start = input_file_fp.tell()
                line = input_file_fp.readline()

        print_to_console("Data processed in: {0}".format(datetime.datetime.now() - start_time))

    def merge_and_create_output(self, clear_temp=True):

        """
        This method merges all the output file for each fingerprint into a single file and
        deletes the temporary files
        :param clear_temp:  Clears individual fingerprint file if True
        """
        start_time = datetime.datetime.now()
        print_to_console("Data cleaning started at: {0}".format(start_time))

        temp_directory_file_paths = self.temp_directory + '/*' + JSONLINE_EXTENSION
        with open(self.output_file, 'wb') as outfile:
            for filename in glob.glob(temp_directory_file_paths):
                with open(filename, 'rb') as readfile:
                    shutil.copyfileobj(readfile, outfile)

        if clear_temp:
            clean_directory(self.temp_directory)

        print_to_console("Data cleaned in: {0}".format(datetime.datetime.now() - start_time))


if __name__ == '__main__':
    cert_dupl_identifier = CertificateDuplicateIdentifier()
    cert_dupl_identifier.process_data(INPUT_FILE, OUTPUT_DIRECTORY)
    cert_dupl_identifier.merge_and_create_output()
