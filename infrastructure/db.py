import mysql.connector
from mysql.connector import Error
from mysql.connector.pooling import MySQLConnectionPool
from dotenv import load_dotenv
import os

load_dotenv()

DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': os.getenv('DB_NAME', 'app_money')
}

_connection_pool = None


def _get_connection_pool():
    global _connection_pool
    if _connection_pool is None:
        try:
            _connection_pool = MySQLConnectionPool(
                pool_name='app_money_pool',
                pool_size=int(os.getenv('DB_POOL_SIZE', '5')),
                pool_reset_session=True,
                **DB_CONFIG,
            )
        except Error:
            _connection_pool = False
    return _connection_pool

def get_connection():
    try:
        pool = _get_connection_pool()
        if pool:
            connection = pool.get_connection()
        else:
            connection = mysql.connector.connect(**DB_CONFIG)
        if connection.is_connected():
            return connection
    except Error as e:
        return None
