#!/usr/bin/env python3

import os
import errno
import datetime
import time
import json
import argparse
import sys
import shutil
import hashlib
import tarfile
import zipfile
import traceback
import base64
import logging
import re
import glob
from hashlib import md5
from collections import defaultdict
from operator import xor

script_run_path = os.path.abspath(os.path.dirname(__file__))

class key_strings():
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details_key = "details"
        self.artifacts_key = "artifacts"

        self.name_key = "name"
        self.version_key = "version"
        self.commitid_key = "commit_id"
        self.checksum_key = "checksum"

        self.system_date_key = "system_date"
        self.details_checksum_key = "checksum"
        self.pkg_version_key = "version"
        self.bot_variant_key = "bot_variant"
        self.target_system_key = "system"

        self.afct_info_json_fname = "artifacts_info.json"
        self.artifacts_folder_name = "artifacts"

class pkg_configs():
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.extract_path_prefix = "data/fw/prog/"

class PackageVerifError(Exception):
    def __init__(self, message, payload=None):
        self.message = message
        self.payload = payload # you could add more args
    def __str__(self):
        return str(self.message)

class FileVerifError(Exception):
    def __init__(self, message, payload=None):
        self.message = message
        self.payload = payload # you could add more args
    def __str__(self):
        return str(self.message)

class FileHandler:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.filepath = os.path.abspath(__file__)

    def get_pkg_basename(self, abs_filepath) -> str:
        name = os.path.basename(abs_filepath)
        regex_pattern1 = r"(\w+?)_([vV]?)(\d+).?"
        regex_pattern2 = r"(\w+)([vV]?).*"
        if re.search(regex_pattern1, name):
            try:
                name_list = re.match(regex_pattern1, name)
                name = name_list.groups()[0]
            except:
                if name_list:
                    print(name_list.groups())
                name = name.split('.')[0]

        elif re.search(regex_pattern2, name):
            print('#')
            try:
                name_list = re.match(regex_pattern2, name)
                name = name_list.groups()[0]
            except:
                if name_list:
                    print(name_list.groups())
                name = name.split('.')[0]
        return name

    def generate_md5(self, fname, chunk_size=4096)->str:
        """
        Function which takes a file name and returns md5 checksum of the file
        """
        try:
            hash = hashlib.md5()
            with open(fname, "rb") as f:
                # Read the 1st block of the file
                chunk = f.read(chunk_size)
                # Keep reading the file until the end and update hash
                while chunk:
                    hash.update(chunk)
                    chunk = f.read(chunk_size)
        except IOError as err:
            raise

        return hash.hexdigest()

    def read_input_json(self, filepath=None):
        json_load = {}
        try:
            if (os.path.isfile(filepath)):
                with open(filepath, 'r') as ip_json:
                    json_load = json.load(ip_json)
                return json_load
            else:
                raise Exception("Provided Path is Not a Valid FilePath")
        except ValueError:
            print("Incorrect JSON value or syntax")
        except:
            raise

    def delete_existing(self, path=None):
        try:
            if path is not None:
                if os.path.isfile(path):
                    os.remove(path)
                elif os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    pass
        except:
            raise
    
    def extract_zip(self, archive_path=None, unpack_path=None) -> str:
        """ 
        Extract the archive and return the common path for the archive
        """
        common_path = None
        try:
            if archive_path is None:
                raise Exception("Archive path is not provided")
            if unpack_path is None:
                raise Exception("Unpack Path is not provided")
            print(archive_path)
            archive_obj = None
            if tarfile.is_tarfile(archive_path):
                try:
                    archive_obj = tarfile.open(name=archive_path, mode='r')
                    common_path = os.path.commonpath(archive_obj.getnames())
                    archive_obj.extractall(unpack_path)
                    time.sleep(0.5)
                    archive_obj.close()
                except:
                    archive_obj.close()
                    raise
            elif zipfile.is_zipfile(archive_path):
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(unpack_path)
            else:
                try:
                    shutil.unpack_archive(archive_path, unpack_path)
                except:
                    raise FileVerifError("Unknown archive type found")
        except ValueError as vale:
            raise Exception("File provided is not a valid archive: {}".format(vale))
        except:
            raise

        return common_path
    
    def delete_existing_inside(self, path=None):
        """
        This method deletes all the files/folder inside path
        """
        try:
            if (path is None) or (not os.path.exists(path)):
                print("Path to delete is None")
                return

            if not os.listdir(path):
                print("Nothing to delete Inside Path:{}".format(path))
            
            for filename in os.listdir(path):
                file_path = os.path.join(path, filename)
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)

        except:
            raise
    
    def perform_housekeeping(self, housekeep_path, pkgname):
        """ 
        Deletes all files and folders having above pkgname as regex
        """

        try:
            pkg_basename = self.get_pkg_basename(pkgname)

            # Get all folders starting with above basename and delete them
            files_list = glob.glob(os.path.join(housekeep_path, pkg_basename) + "*")
            for file in files_list:
                print("PKG File/Folder: {} going to be deleted".format(file))
                self.delete_existing(os.path.join(os.getcwd(), file))
        except:
            print("Unable to perform housekeeping properly")

    def gen_combined_checksum(self, md5sum_list=[]) -> str:
        final_hash = int(md5sum_list[0], 16)
        for each in md5sum_list[1:]:
            final_hash = xor(final_hash, int(each, 16))
        return(str(final_hash)[:32])


class extract_pkg(key_strings, pkg_configs, FileHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        self.logger = None
        self.verif_status = False
        self.folder_name = "default"
        self.filepath_abs = None
        self.extract_path_abs = None
        self.json_checksum = {}
        self.pkg_details = {}
        self.verification_status = False
        self.artifacts_list = []
        self.artifact_info = {}
        self.validate=False

    def pkg_extract_main(self, filepath_arg=None, validate=False):
        self.validate = validate
        self.verif_status = True

        try:
            if __name__ == "__main__":
                print("Running Extractor in Standalone Mode")
            else:
                print("Running Extractor in API Mode")
                print(logging.getLogger().parent)
                # use the logger (root) from main application
                if (logging.getLogger().hasHandlers()):
                    self.logger = logging.getLogger()
                    logging.StreamHandler(stream=sys.stdout)

            if(filepath_arg is None):
                raise Exception("Filepath is not provided")
            elif(not os.path.exists(filepath_arg)):
                raise Exception("Provided filepath doens't exists")
            elif(not os.path.isfile(filepath_arg)):
                raise Exception("Provided filepath is not a valid file")
            elif(not (os.path.getsize(filepath_arg) > 0)):
                raise Exception("Provided Filesize is zero")
            else:
                pass
            
            self.filepath_abs = os.path.abspath(filepath_arg)

            self.perform_housekeeping(self.extract_path_prefix, os.path.basename(self.filepath_abs))
            self.extract_artifacts()
        except PackageVerifError as pkge:
            self.delete_existing(self.extract_path_abs)
            raise
        except:
            raise
        else:
            if self.verification_status:
                print("Artifacts Verification Successful")

    def extract_artifacts(self):
        print("Extracting Artifacts...")
        try:
            folder_name = self.extract_zip(self.filepath_abs, self.extract_path_prefix)
            self.extract_path_abs = os.path.join(self.extract_path_prefix, folder_name)
            if self.validate:
                self.validate_artifacts()
            else:
                print("Skipping validation")
                pass
        except:
            raise

    def validate_artifacts(self):
        json_fpath = os.path.join(self.extract_path_abs, self.afct_info_json_fname)
        try:
            if (not os.path.isfile(json_fpath)):
                raise PackageVerifError("JSON File not Present in the package")
            json_load = self.read_input_json(json_fpath)
            self.parse_json_file(json_load)
        except:
            raise

        md5sum_list = []
        try:
            for dirpath, subdirs, files in os.walk(os.path.join(self.extract_path_abs, self.artifacts_folder_name)):
                basepath = os.path.abspath(dirpath)
                for file in files:
                    checksum = self.generate_md5(os.path.join(basepath, file))

                    if checksum != self.json_checksum[file]:
                        raise PackageVerifError("Fname: {}, Checksum Not Matching".format(file))
                    else:
                        md5sum_list.append(checksum)
                        self.artifacts_list.append(os.path.join(basepath, file))

            global_chksum = self.gen_combined_checksum(md5sum_list)
            if global_chksum != self.pkg_details[self.details_checksum_key]:
                print("FileGlobal Chksum: {}".format(self.pkg_details[self.details_checksum_key]))
                print("GenGlobal Chksum: {}".format(global_chksum))
                raise PackageVerifError("Global Checksum Not Matching")

        except PackageVerifError as pve:
            self.delete_existing(self.extract_path_abs)
            self.verification_status = False
            raise
        except:
            raise
        else:
            self.verification_status = True
            
    def get_artifacts_path(self):
        return self.artifacts_list
    
    def get_artifacts_info(self):
        return self.artifact_info
    
    def get_extract_path_abs(self):
        return self.extract_path_abs

    def parse_json_file(self, json_data):
        try:
            # Parse artifacts info
            for key in json_data[self.artifacts_key].keys():
                self.json_checksum[json_data[self.artifacts_key][key][self.name_key]] = json_data[self.artifacts_key][key][self.checksum_key]
                self.artifact_info[json_data[self.artifacts_key][key][self.name_key]] = json_data[self.artifacts_key][key]

            # Parse Details
            self.pkg_details = json_data[self.details_key]
        except KeyError as ke:
            raise PackageVerifError("Unknown Key error while Chksum Parsing")
        except:
            raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', dest = "PackageFile", default = None, type = str, help = 'Specify the PATH to Input Package File')
    args = vars(parser.parse_args())

    ip_pkg_path = str(args["PackageFile"])

    try:
        if not os.path.exists(ip_pkg_path):
            print("Provide DIR path as argument")
            sys.exit(0)

        pkg_obj = extract_pkg()
        pkg_obj.pkg_extract_main(ip_pkg_path, validate=True)
    except:
        traceback.print_exc()