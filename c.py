import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import bcrypt
import time
import boto3

# Set page configuration
st.set_page_config(page_title="Criminal Management System", page_icon="🚔", layout="wide")

# Updated CSS for dark/light mode compatibility
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Roboto', sans-serif;
    }
    
    /* Card styling with theme compatibility */
    .stat-card {
        background-color: var(--background-color);
        border: 1px solid var(--border-color);
        border-radius: 10px;
        padding: 20px;
        text-align: center;
        box-shadow: var(--box-shadow);
        margin: 10px 0;
    }
    
    /* Dynamic variables for light/dark modes */
    :root {
        --background-color: rgba(255, 255, 255, 0.1);
        --border-color: rgba(128, 128, 128, 0.2);
        --box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        --text-color: inherit;
    }
    
    /* Dark mode overrides */
    [data-theme="dark"] {
        --background-color: rgba(0, 0, 0, 0.2);
        --border-color: rgba(255, 255, 255, 0.1);
        --box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
    }
    
    .stat-card h3 {
        font-size: 18px;
        margin-bottom: 10px;
        color: var(--text-color);
    }
    
    .stat-card p {
        font-size: 24px;
        font-weight: bold;
        color: #3498db;
    }
    
    /* Button styling with theme compatibility */
    .stButton>button {
        background-color: #3498db;
        color: white;
        border-radius: 5px;
        border: none;
        padding: 10px 20px;
        font-weight: bold;
        transition: all 0.3s ease;
    }
    
    .stButton>button:hover {
        background-color: #2980b9;
        box-shadow: var(--box-shadow);
    }
    
    /* Form and input styling */
    .stTextInput>div>div>input,
    .stSelectbox>div>div,
    .stTextArea>div>textarea {
        background-color: var(--background-color);
        border-color: var(--border-color);
        color: var(--text-color);
    }
    
    /* DataFrame styling */
    .stDataFrame {
        background-color: var(--background-color);
        border-radius: 10px;
        border: 1px solid var(--border-color);
    }
    
    /* Header styling */
    h1, h2, h3 {
        color: var(--text-color);
        font-weight: bold;
    }
    
    /* Expander styling */
    .streamlit-expanderHeader {
        background-color: var(--background-color);
        border: 1px solid var(--border-color);
    }
    
    /* Metric styling */
    .stMetric {
        background-color: var(--background-color);
        border: 1px solid var(--border-color);
        border-radius: 10px;
        padding: 10px;
    }
</style>
""", unsafe_allow_html=True)

class CriminalManagementSystem:
    def __init__(self):
        self.conn = sqlite3.connect('criminal_records.db')
        self.c = self.conn.cursor()
        self.create_tables()
        self.create_triggers()

    def create_tables(self):
        self.c.execute('''CREATE TABLE IF NOT EXISTS criminal
                         (id INTEGER PRIMARY KEY AUTOINCREMENT,
                          name TEXT,
                          crime_location TEXT,
                          occupation TEXT,
                          arrest_date TEXT,
                          crime_date TEXT,
                          crime_type TEXT,
                          address TEXT,
                          father_name TEXT,
                          age INTEGER,
                          gender TEXT)''')

        self.c.execute('''CREATE TABLE IF NOT EXISTS log
                          (log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                           action TEXT,
                           record_id INTEGER,
                           timestamp TEXT)''')

        self.c.execute('''CREATE TABLE IF NOT EXISTS deleted_records
                          (id INTEGER PRIMARY KEY AUTOINCREMENT,
                           original_id INTEGER,
                           name TEXT,
                           crime_location TEXT,
                           occupation TEXT,
                           arrest_date TEXT,
                           crime_date TEXT,
                           crime_type TEXT,
                           address TEXT,
                           father_name TEXT,
                           age INTEGER,
                           gender TEXT,
                           deletion_date TEXT)''')

        self.c.execute('''CREATE TABLE IF NOT EXISTS users
                          (id INTEGER PRIMARY KEY AUTOINCREMENT,
                           username TEXT UNIQUE,
                           password TEXT,
                           role TEXT)''')
        self.conn.commit()

    def create_triggers(self):
        self.c.execute('''
        CREATE TRIGGER IF NOT EXISTS log_insert
        AFTER INSERT ON criminal
        BEGIN
            INSERT INTO log (action, record_id, timestamp)
            VALUES ('INSERT', NEW.id, datetime('now'));
        END;
        ''')

        self.c.execute('''
        CREATE TRIGGER IF NOT EXISTS log_update
        AFTER UPDATE ON criminal
        BEGIN
            INSERT INTO log (action, record_id, timestamp)
            VALUES ('UPDATE', NEW.id, datetime('now'));
        END;
        ''')

        self.c.execute('''
        CREATE TRIGGER IF NOT EXISTS log_delete
        AFTER DELETE ON criminal
        BEGIN
            INSERT INTO log (action, record_id, timestamp)
            VALUES ('DELETE', OLD.id, datetime('now'));
        END;
        ''')
        self.conn.commit()

    def add_record(self, record):
        self.c.execute('''INSERT INTO criminal 
                          (name, crime_location, occupation, arrest_date, crime_date, crime_type, 
                           address, father_name, age, gender) 
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', record)
        self.conn.commit()

    def update_record(self, record_id, record):
        self.c.execute('''UPDATE criminal SET
                          name=?, crime_location=?, occupation=?, arrest_date=?, crime_date=?, 
                          crime_type=?, address=?, father_name=?, age=?, gender=?
                          WHERE id=?''', record + (record_id,))
        self.conn.commit()

    def delete_record(self, record_id):
        self.c.execute("SELECT * FROM criminal WHERE id=?", (record_id,))
        record = self.c.fetchone()
        
        if record:
            self.c.execute('''INSERT INTO deleted_records 
                              (original_id, name, crime_location, occupation, arrest_date, crime_date, 
                               crime_type, address, father_name, age, gender, deletion_date)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))''', record)
            
            self.c.execute("DELETE FROM criminal WHERE id=?", (record_id,))
            self.conn.commit()

    def search_records(self, criterion, value):
        query = f"SELECT * FROM criminal WHERE {criterion} LIKE ?"
        self.c.execute(query, ('%' + value + '%',))
        return self.c.fetchall()

    def get_all_records(self):
        self.c.execute("SELECT * FROM criminal")
        return self.c.fetchall()

    def get_crime_statistics(self):
        self.c.execute("SELECT crime_type, COUNT(*) FROM criminal GROUP BY crime_type")
        return self.c.fetchall()

    def get_crime_by_location(self):
        self.c.execute("SELECT crime_location, COUNT(*) FROM criminal GROUP BY crime_location")
        return self.c.fetchall()

    def get_deleted_records(self):
        self.c.execute("SELECT * FROM deleted_records")
        return self.c.fetchall()
    
    def restore_record(self, record_id):
        self.c.execute("SELECT * FROM deleted_records WHERE original_id=?", (record_id,))
        record = self.c.fetchone()
    
        if record:
            self.c.execute('''INSERT INTO criminal
                          (id, name, crime_location, occupation, arrest_date, crime_date, 
                           crime_type, address, father_name, age, gender)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', (record[1],) + record[2:12])
        
            self.c.execute("DELETE FROM deleted_records WHERE original_id=?", (record_id,))
            self.conn.commit()
            return True
        return False

    def add_user(self, username, password, role):
        try:
            # Option 1: Using DynamoDB
            try:
                # Create a DynamoDB resource
                dynamodb = boto3.resource('dynamodb')
                users_table = dynamodb.Table('users')
                
                # Hash the password
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                
                # Create the user item
                user_item = {
                    'username': username,
                    'password': hashed_password.decode('utf-8'),  # Store as string
                    'role': role,
                    'created_at': datetime.now().isoformat()
                }
                
                # Add the user to DynamoDB
                users_table.put_item(Item=user_item)
                print(f"User '{username}' added successfully to DynamoDB.")
                return True
            except Exception as e:
                print(f"Error adding user to DynamoDB: {e}")
                # Fall back to SQLite if DynamoDB fails
                
            # Option 2: Using SQLite (fallback)
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            self.c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                          (username, hashed_password.decode('utf-8'), role))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Error adding user: {e}")
            return False

    def authenticate_user(self, username, password):
        try:
            # Option 1: Try DynamoDB first
            try:
                # Create a DynamoDB resource
                dynamodb = boto3.resource('dynamodb')
                users_table = dynamodb.Table('users')
                
                # Query for the user
                response = users_table.get_item(Key={'username': username})
                
                # Check if user exists
                if 'Item' in response:
                    user = response['Item']
                    
                    # Check password
                    if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                        return user['role']
            except Exception as e:
                print(f"DynamoDB authentication failed: {e}")
                # Fall back to SQLite
            
            # Option 2: Fall back to SQLite
            self.c.execute("SELECT password, role FROM users WHERE username=?", (username,))
            result = self.c.fetchone()
            
            if result:
                stored_password, role = result
                if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                    return role
            
            return None
        except Exception as e:
            print(f"Authentication error: {e}")
            return None

def parse_date(date_str):
    try:
        return pd.to_datetime(date_str)
    except:
        return None

def home_view(cms):
    st.title("🏛 Criminal Management System")
    st.markdown("Welcome to the next-generation Criminal Management System. Efficiently manage and analyze criminal records with our advanced tools and intuitive interface.")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        total_records = len(cms.get_all_records())
        st.markdown(
            f"""
            <div class="stat-card">
                <h3>📊 Total Records</h3>
                <p>{total_records}</p>
            </div>
            """,
            unsafe_allow_html=True
        )
    
    with col2:
        crime_types = len(cms.get_crime_statistics())
        st.markdown(
            f"""
            <div class="stat-card">
                <h3>🏷 Crime Types</h3>
                <p>{crime_types}</p>
            </div>
            """,
            unsafe_allow_html=True
        )
    
    with col3:
        all_records = cms.get_all_records()
        recent_records = sum(1 for r in all_records if parse_date(r[4]) and parse_date(r[4]) > datetime.now() - timedelta(days=30))
        st.markdown(
            f"""
            <div class="stat-card">
                <h3>🆕 Recent Records (30 days)</h3>
                <p>{recent_records}</p>
            </div>
            """,
            unsafe_allow_html=True
        )
    
    st.markdown("### 🔍 Quick Search")
    
    crime_types = ["All"] + [crime[0] for crime in cms.get_crime_statistics()]
    selected_crime_type = st.selectbox("Select crime type", crime_types)
    
    if st.button("Search"):
        if selected_crime_type == "All":
            results = cms.get_all_records()
        else:
            results = cms.search_records("crime_type", selected_crime_type)
        
        if results:
            st.dataframe(pd.DataFrame(results, columns=["ID", "Name", "Crime Location", "Occupation", 
                                                        "Arrest Date", "Crime Date", "Crime Type", 
                                                        "Address", "Father's Name", "Age", "Gender"]))
        else:
            st.warning("No records found")

def manage_records_view(cms, is_admin=False):
    st.title("📝 Manage Criminal Records")

    record_menu = ["Add", "View", "Update"]
    if is_admin:
        record_menu.append("Delete")
    record_choice = st.sidebar.radio("Record Operations", record_menu)

    if record_choice == "Add":
        st.subheader("📥 Add New Criminal Record")
        with st.form("add_record_form"):
            col1, col2 = st.columns(2)
            with col1:
                name = st.text_input("Name")
                crime_location = st.text_input("Crime Location")
                occupation = st.text_input("Occupation")
                arrest_date = st.date_input("Arrest Date")
                crime_date = st.date_input("Crime Date")
            with col2:
                crime_type = st.text_input("Crime Type")
                address = st.text_area("Address")
                father_name = st.text_input("Father's Name")
                age = st.number_input("Age", min_value=0, max_value=120)
                gender = st.selectbox("Gender", ["Male", "Female", "Other"])

            if st.form_submit_button("Add Record"):
                with st.spinner("Adding record..."):
                    cms.add_record((name, crime_location, occupation, str(arrest_date), str(crime_date),
                                    crime_type, address, father_name, age, gender))
                    st.success("Record Added Successfully")

    elif record_choice == "View":
        st.subheader("🔎 View Criminal Records")
        search_criterion = st.selectbox("Search By", ["id", "name", "crime_type", "crime_location"])
        search_value = st.text_input("Enter Search Value")

        if st.button("Search"):
            with st.spinner("Searching records..."):
                search_results = cms.search_records(search_criterion, search_value)
                if search_results:
                    df = pd.DataFrame(search_results, columns=["ID", "Name", "Crime Location", "Occupation", 
                                                               "Arrest Date", "Crime Date", "Crime Type", 
                                                               "Address", "Father's Name", "Age", "Gender"])
                    st.dataframe(df)
                else:
                    st.warning("No records found")

        if st.button("View All Records"):
            with st.spinner("Loading all records..."):
                all_records = cms.get_all_records()
                if all_records:
                    df = pd.DataFrame(all_records, columns=["ID", "Name", "Crime Location", "Occupation", 
                                                            "Arrest Date", "Crime Date", "Crime Type", 
                                                            "Address", "Father's Name", "Age", "Gender"])
                    st.dataframe(df)
                else:
                    st.warning("No records found in the database")

    elif record_choice == "Update":
        st.subheader("🔄 Update Criminal Record")
        record_id = st.number_input("Enter Record ID to Update", min_value=1)
        record = cms.search_records("id", str(record_id))

        if record:
            record = record[0]
            with st.form("update_record_form"):
                col1, col2 = st.columns(2)
                with col1:
                    name = st.text_input("Name", record[1])
                    crime_location = st.text_input("Crime Location", record[2])
                    occupation = st.text_input("Occupation", record[3])
                    arrest_date = st.date_input("Arrest Date", parse_date(record[4]) or datetime.now())
                    crime_date = st.date_input("Crime Date", parse_date(record[5]) or datetime.now())
                with col2:
                    crime_type = st.text_input("Crime Type", record[6])
                    address = st.text_area("Address", record[7])
                    father_name = st.text_input("Father's Name", record[8])
                    age = st.number_input("Age", min_value=0, max_value=120, value=record[9])
                    gender = st.selectbox("Gender", ["Male", "Female", "Other"], index=["Male", "Female", "Other"].index(record[10]))

                if st.form_submit_button("Update Record"):
                    with st.spinner("Updating record..."):
                        cms.update_record(record_id, (name, crime_location, occupation, str(arrest_date), str(crime_date),
                                                      crime_type, address, father_name, age, gender))
                        st.success("Record Updated Successfully")
        else:
            st.warning("Record not found")

    elif record_choice == "Delete" and is_admin:
        st.subheader("🗑 Delete Criminal Record")
        record_id = st.number_input("Enter Record ID to Delete", min_value=1)
        if st.button("Delete Record"):
            with st.spinner("Deleting record..."):
                cms.delete_record(record_id)
                st.success("Record Deleted Successfully")

def statistics_view(cms):
    st.title("📊 Criminal Statistics")
    crime_stats = cms.get_crime_statistics()
    location_stats = cms.get_crime_by_location()
    
    df_crime = pd.DataFrame(crime_stats, columns=["Crime Type", "Count"])
    df_location = pd.DataFrame(location_stats, columns=["Location", "Count"])
    
    fig_bar = px.bar(df_crime, x="Crime Type", y="Count", title="Crimes by Type",
                     labels={"Count": "Number of Crimes"},
                     color="Count", color_continuous_scale="Viridis")
    st.plotly_chart(fig_bar, use_container_width=True)

    fig_pie = px.pie(df_crime, values="Count", names="Crime Type", title="Crime Type Distribution")
    st.plotly_chart(fig_pie, use_container_width=True)

    fig_location = px.bar(df_location, x="Location", y="Count", title="Crimes by Location",
                           labels={"Count": "Number of Crimes"},
                           color="Count", color_continuous_scale="Viridis")
    st.plotly_chart(fig_location, use_container_width=True)

    with st.expander("View Crime Statistics Data"):
        st.dataframe(df_crime)
        st.dataframe(df_location)

    st.subheader("📈 Additional Insights")
    col1, col2 = st.columns(2)
    
    with col1:
        total_crimes = df_crime["Count"].sum()
        st.metric("Total Crimes Recorded", total_crimes)
        
        most_common_crime = df_crime.loc[df_crime["Count"].idxmax(), "Crime Type"] if not df_crime.empty else "N/A"
        st.metric("Most Common Crime", most_common_crime)
    
    with col2:
        avg_crimes_per_type = df_crime["Count"].mean() if not df_crime.empty else 0
        st.metric("Average Crimes per Type", f"{avg_crimes_per_type:.2f}")
        
        crime_types_count = len(df_crime)
        st.metric("Number of Crime Types", crime_types_count)

def deleted_records_view(cms):
    st.title("🗑 Deleted Records")
    deleted_records = cms.get_deleted_records()
    
    if deleted_records:
        df_deleted = pd.DataFrame(deleted_records, columns=["ID", "Original ID", "Name", "Crime Location", "Occupation", 
                                                            "Arrest Date", "Crime Date", "Crime Type", 
                                                            "Address", "Father's Name", "Age", "Gender", "Deletion Date"])
        st.dataframe(df_deleted)
        restore_id = st.number_input("Enter Record ID to Restore", min_value=1)
        if st.button("Restore Record"):
                if cms.restore_record(restore_id):
                    st.success("Record Restored Successfully")
                else:
                    st.warning("Record not found in deleted records")
    else:
        st.info("No deleted records found")

def user_management_view(cms):
    st.subheader("User Management")
    new_username = st.text_input("New Username")
    new_password = st.text_input("New Password", type="password")
    new_role = st.selectbox("Role", ["admin", "user"])
    if st.button("Add User"):
        if cms.add_user(new_username, new_password, new_role):
            st.success("User added successfully")
        else:
            st.error("Failed to add user. Username may already exist.")

def admin_view(cms):
    st.title("Admin Dashboard")
    menu = ["Home", "Manage Records", "Statistics", "Deleted Records", "User Management"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Home":
        home_view(cms)
    elif choice == "Manage Records":
        manage_records_view(cms, is_admin=True)
    elif choice == "Statistics":
        statistics_view(cms)
    elif choice == "Deleted Records":
        deleted_records_view(cms)
    elif choice == "User Management":
        user_management_view(cms)

def user_view(cms):
    st.title("User Dashboard")
    menu = ["Home", "Manage Records", "Statistics"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Home":
        home_view(cms)
    elif choice == "Manage Records":
        manage_records_view(cms, is_admin=False)
    elif choice == "Statistics":
        statistics_view(cms)

def main():
    st.sidebar.title("🚔 Crime Data Hub")
    cms = CriminalManagementSystem()
    
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.role = None

    if not st.session_state.logged_in:
        st.title("🔐 Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            role = cms.authenticate_user(username, password)
            if role:
                st.session_state.logged_in = True
                st.session_state.role = role
                st.success(f"Logged in as {role}")
                st.rerun()
            else:
                st.error("Invalid username or password")
    else:
        if st.session_state.role == 'admin':
            admin_view(cms)
        else:
            user_view(cms)

        if st.sidebar.button("Logout"):
            st.session_state.logged_in = False 
            st.session_state.role = None
            st.rerun()

if __name__ == "__main__":
    main()

# Uncomment and run once to add the first admin user
cms = CriminalManagementSystem()
cms.add_user("admin", "admin_password","admin")
