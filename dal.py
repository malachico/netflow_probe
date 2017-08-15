import pymongo
from pymongo import MongoClient

g_db = None


def get_session_id(session):
    """
    Given a session return its 5-tuple and start time of the session which represent session id
    in addition it returns the timestamp

    :param session:
    :return:
    """
    return {'src_ip': session['src_ip'], 'src_port': session['src_port'], 'dest_ip': session['dest_ip'],
            'dest_port': session['dest_port'], 'protocol': session['protocol'], 'start_time': session['start_time']}


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
         ("dest_port", pymongo.DESCENDING), ("protocol", pymongo.DESCENDING), ("start_time", pymongo.DESCENDING)])


# ### Sessions handling ### #
def upsert_session(session_data):
    """
    Given a session - insert if not exist, update if exist
    :param session_data
    :return: None
    """
    g_db['sessions'].update(
        get_session_id(session_data),
        {
            "$set": session_data,
        },
        upsert=True
    )
