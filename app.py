import streamlit as st
from db_config import get_db_connection
from auth import register_user, authenticate_user
from encryption import save_encrypted_file, read_encrypted_file
from audit import log_action, fetch_audit_logs
from utils import validate_username, validate_password_strength
import pandas as pd
import os

st.set_page_config(page_title='Secure File System', layout='centered')

if 'user' not in st.session_state:
    st.session_state['user'] = None


def require_login():
    if not st.session_state['user']:
        st.warning('Please login or register to continue.')
        st.stop()


st.title('🔐 Secured File Access and Sharing System')
menu = st.sidebar.selectbox('Menu', ['Login', 'Register', 'Upload', 'My Files', 'Audit Logs'])

if menu == 'Register':
    st.header('Register New Account')
    username = st.text_input('Username')
    password = st.text_input('Password', type='password')
    role = st.selectbox('Role', ['user'], disabled=True)
    if st.button('Create Account'):
        if not validate_username(username):
            st.error('Invalid username. Use 3-48 chars: letters, numbers, ., -, _')
        elif not validate_password_strength(password):
            st.error('Password too weak. Min 8 chars, include upper, lower, digit.')
        else:
            try:
                uid = register_user(username, password, role)
                st.success(f'User created (id: {uid}). Please login.')
            except Exception as e:
                st.error(f'Error creating user: {e}')

elif menu == 'Login':
    st.header('Login')
    username = st.text_input('Username')
    password = st.text_input('Password', type='password')
    if st.button('Login'):
        user = authenticate_user(username, password)
        if user:
            st.session_state['user'] = user
            st.success(f'Welcome, {username}!')
            log_action(user['id'], 'login', ip_address=None)
        else:
            st.error('Invalid credentials')

elif menu == 'Upload':
    require_login()
    st.header('Upload a File (it will be encrypted)')
    uploaded = st.file_uploader('Choose file', type=None)
    if uploaded and st.button('Upload'):
        data = uploaded.read()
        safe_path = save_encrypted_file(uploaded.name, data)
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute('INSERT INTO files (filename, owner_id, file_path) VALUES (%s, %s, %s)',
                        (uploaded.name, st.session_state['user']['id'], safe_path))
            conn.commit()
            st.success('File encrypted and uploaded successfully')
            log_action(st.session_state['user']['id'], f'upload:{uploaded.name}')
        finally:
            cur.close(); conn.close()

elif menu == 'My Files':
    require_login()
    st.header('Your Uploaded Files')
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('SELECT id, filename, file_path, upload_time FROM files WHERE owner_id=%s', (st.session_state['user']['id'],))
        rows = cur.fetchall()
    finally:
        cur.close(); conn.close()

    if not rows:
        st.info('No files uploaded yet')
    else:
        df = pd.DataFrame(rows, columns=['id', 'filename', 'file_path', 'upload_time'])
        st.dataframe(df[['id', 'filename', 'upload_time']])
        selected = st.selectbox('Select file to download', df['filename'].tolist())
        if st.button('Download'):
            record = df[df['filename'] == selected].iloc[0]
            dec = read_encrypted_file(record['file_path'])
            st.download_button(label='Click to download', data=dec, file_name=record['filename'])
            log_action(st.session_state['user']['id'], f'download:{selected}')

elif menu == 'Audit Logs':
    require_login()
    st.header('Audit Logs')
    try:
        df = fetch_audit_logs()
        if df.empty:
            st.info('No audit logs yet')
        else:
            st.dataframe(df)
    except Exception as e:
        st.error(f'Unable to fetch logs: {e}')


st.markdown('---')
st.caption('This app encrypts files locally before saving and logs actions to MySQL. Use for demo/poc only.')