import pymongo
from pymongo import MongoClient

g_db = None


def get_session_id(session):
    """
    Given a session return its 5-tuple which represent session id

    :param session:
    :return:
    """
    return {'src_ip': session['src_ip'], 'src_port': session['src_port'], 'dest_ip': session['dest_ip'],
            'dest_port': session['dest_port'], 'protocol': session['protocol']}


def init_db():
    """
    initial database
    :return:
    """
    global g_db

    # Create client
    client = MongoClient()

    # Create db connection
    g_db = client['collector']

    g_db.sessions.create_index(
        [("src_ip", pymongo.DESCENDING), ("src_port", pymongo.DESCENDING), ("dest_ip", pymongo.DESCENDING),
         ("dest_port", pymongo.DESCENDING), ("protocol", pymongo.DESCENDING)])


# ### Sessions handling ### #
def upsert_session(session_data):
    """
    Given a session - insert if not exist, update if exist
    :param ip_frame:
    :param timestamp: timestamp of the session
    :return: None
    """
    g_db['sessions'].update(
        get_session_id(session_data),
        {
            "$set": session_data,
            "$inc": {'n_bytes': session_data['bytes_count'], 'n_packets': session_data['packets_count']},
            "$setOnInsert": {'start_time': session_data['start_time']}
        },
        upsert=True
    )

