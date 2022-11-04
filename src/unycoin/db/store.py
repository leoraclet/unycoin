# Copyright (c) 2022 Neutronys

# The software is distributed under the MIT software license
# See the accompanying file LICENSE in the main directory of
# the project for more details.


"""

This file implements database operations.

"""


from dataclasses import dataclass

import sqlite3


class DB:

    """
    Database class
    """

    def __init__(self, path='database.sqlite3'):

        self.conn = None
        self.curs = None
        self.path = path

    def connect(self):

        """
        Open database connection
        """

        try:
            self.conn = sqlite3.connect(self.path)
            self.curs = self.conn.cursor()

        except FileNotFoundError:
            pass

    def disconnect(self):

        """
        Close database connection
        """

        self.curs.close()
        self.conn.close()


@dataclass
class Model:

    """
    Generic model class
    """

    columns: [str]
    table: str

    def insert(self):
        pass


if __name__ == '__main__':
    pass
