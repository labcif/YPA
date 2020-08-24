from gui import GUI
import logging
import os


def main(temp_dir):
    logger = logging.getLogger('parser')
    logger.setLevel(logging.DEBUG)
    debug_log_path = os.path.join(temp_dir, 'debug.log')
    fh = logging.FileHandler(debug_log_path)
    fh.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    return GUI()

if __name__ == "__main__":
    main()
