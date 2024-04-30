from flask import Flask, render_template, request, redirect, url_for, flash
from kubernetes import client, config
import jenkins
import subprocess
import json
import git
import requests
import base64
import docker
from flask import Flask, jsonify
import re
import xml.etree.ElementTree as ET
from flask import request, redirect, url_for
import secrets
from flask import Flask, render_template, request, redirect, url_for, session
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user

from flask import Flask, request, render_template, redirect, url_for
import requests
import json
from urllib.parse import quote
import requests
import base64
from flask import Flask, request, render_template
import git
import git
import base64
from flask import Flask, request, render_template, redirect, url_for
from flask import Flask, render_template, request, redirect, url_for, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_login import login_required
from mongoengine import Document, StringField, DateTimeField
from datetime import datetime
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import secrets
from flask import Flask, render_template, request, redirect, flash, url_for
from flask_mail import Mail, Message
import smtplib
import ssl
from email.message import EmailMessage





app = Flask(__name__)
mail = Mail(app)

app.secret_key = secrets.token_hex(16)

app.config['MONGO_URI'] = 'mongodb://localhost:27017/mydatabase'

mongo = PyMongo(app)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']
        users = mongo.db.users
        users.insert_one({'username': username, 'password': password, 'role': role, 'approved': False})
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users = mongo.db.users
        user_data = users.find_one({'username': username, 'approved': True})
        if user_data and check_password_hash(user_data['password'], password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username/password combination or account not approved', 'error')
            return render_template('login.html')
    return render_template('login.html')
    
    
    
# Define email sender and receiver
email_sender = 'lasslass27@gmail.com'
email_password = 'tnjs tvxi yyzc cnmc'

# Set the subject and body of the email
subject = 'LEARNOPS'
body = """
Your password has been successfully reset
"""


    
    
    
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']  # Get the email input
        new_password = request.form['new_password']
        users = mongo.db.users
        user_data = users.find_one({'username': username, 'approved': True})
        if user_data:
            # Update the user's password
            users.update_one({'username': username}, {'$set': {'password': generate_password_hash(new_password)}})
            # Send password reset confirmation email
            send_password_reset_email(email)
            flash('Password reset successful. You can now login with your new password.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username not found or account not approved', 'error')
            return render_template('forgot_password.html')
    return render_template('forgot_password.html')

def send_password_reset_email(email_receiver):
    msg = EmailMessage()
    msg['From'] = email_sender
    msg['To'] = email_receiver
    msg['Subject'] = subject
    msg.set_content(body)

    # Add SSL (layer of security)
    context = ssl.create_default_context()

    # Log in and send the email
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.send_message(msg)

    






    
    
    


login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, username, password, role='user', is_superuser=False):
        self.username = username
        self.password = password
        self.role = role
        

class User(UserMixin):
    pass
    
@app.route('/manage_users', methods=['GET', 'POST'])
def manage_users():
    role_filter = request.args.get('role')
    users = mongo.db.users

    if role_filter:
        filtered_users = users.find({'role': role_filter})
    else:
        filtered_users = users.find()

    if request.method == 'POST':
        username = request.form['username']
        action = request.form['action']  # 'approve', 'delete'
        user = users.find_one({'username': username})
        if user:
            if action == 'approve':
                users.update_one({'username': username}, {'$set': {'approved': True}})
                flash(f'User {username} approved successfully', 'success')
            elif action == 'delete':
                users.delete_one({'username': username})
                flash(f'User {username} deleted successfully', 'success')
            else:
                flash('Invalid action', 'error')
        else:
            flash('User not found', 'error')

    return render_template('manage_users.html', users=filtered_users)





@login_manager.user_loader
def load_user(user_id):
    user = User()
    user.id = user_id
    return user

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
















































config.load_kube_config()







    
    ############################################################

# Jenkins CONFIGGGGGGGGGGGGGGGGG #
app.secret_key = '11676eb1d5e08db7f5b76801d6e1f853c4'  # Set a unique and secure secret key
host = "http://192.168.192.8:8080"
username = "admin"  # Jenkins username here
password = "270132ba0df449f5b304c2cfa0853ea9"  # Jenkins user password or API token here
server = jenkins.Jenkins(host, username=username, password=password)

# Function to get the total count of jobs from Jenkins
def jobs_count():
    jobs = server.get_jobs()
    return len(jobs)

# Function to check if a job exists in Jenkins
def job_exists(job_name):
    jobs = server.get_jobs()
    job_names = [job['name'] for job in jobs]
    return job_name in job_names

# Route for displaying jobs

@app.route('/jobs')
def display_jobs():
    user = server.get_whoami()
    version = server.get_version()
    jobs = server.get_jobs()
    count = jobs_count()  # Get the total count of jobs
    return render_template('jobs.html', user=user['fullName'], version=version, jobs=jobs, count=count)

# Route for building a job
@app.route('/build_job', methods=['POST'])
def build_job():
    job_name = request.form['job_name']
    server.build_job(job_name)

    # Flash a success message
    flash(f'Build for {job_name} created successfully!', 'success')
    return redirect(url_for('display_jobs'))

# Route for deleting a job
@app.route('/delete_job', methods=['POST'])
def delete_job():
    job_name = request.form['job_name']
    server.delete_job(job_name)

    # Flash a success message
    flash(f'Job {job_name} deleted successfully!', 'success')
    return redirect(url_for('display_jobs'))

# Route for creating a job
@app.route('/create_job', methods=['POST'])
def create_job():
    job_name = request.form['job_name']

    if job_exists(job_name):
        flash(f'Job {job_name} already exists!', 'warning')
    else:
        job_config = jenkins.EMPTY_CONFIG_XML  # You can modify this to suit your job configuration
        server.create_job(job_name, job_config)
        flash(f'Job {job_name} created successfully!', 'success')

    return redirect(url_for('display_jobs'))
    
    
@app.route('/get_pipeline_script', methods=['POST'])
def get_pipeline_script():
    job_name = request.form['job_name']
    pipeline_script = server.get_job_config(job_name)

    # Use regular expressions to extract the pipeline script content
    pattern = re.compile(r'<script>(.*?)</script>', re.DOTALL)
    match = pattern.search(pipeline_script)
    if match:
        pipeline_content = match.group(1)
    else:
        pipeline_content = "Pipeline script not found."

    return render_template('pipeline_script.html', job_name=job_name, pipeline_content=pipeline_content)
    
    
@app.route('/update_pipeline_script', methods=['POST'])
def update_pipeline_script():
    job_name = request.form['job_name']
    updated_script = request.form['updated_script']
    
    # Retrieve the existing pipeline script
    pipeline_script = server.get_job_config(job_name)
    
    # Replace the existing pipeline script with the updated script
    updated_config = re.sub(r'<script>(.*?)</script>', f'<script>{updated_script}</script>', pipeline_script, flags=re.DOTALL)
    
    # Update the pipeline script in Jenkins
    server.reconfig_job(job_name, updated_config)
    
    # Redirect to the page showing the updated pipeline script
    return redirect(url_for('display_jobs', job_name=job_name))
    
    
    ############################################################
    #NEXUS CONFIGGGGGGGGGGG #

@app.route('/nexus')
def nexus():
    # Nexus credentials
    nexus_username = 'admin'
    nexus_password = 'nexus'

    # Execute the curl command to retrieve repositories from the Nexus server
    command = f'curl -X GET http://192.168.192.8:8081/service/rest/v1/repositories -u {nexus_username}:{nexus_password}'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    # Check if the command executed successfully and return the result directly
    if result.returncode == 0:
        repositories = json.loads(result.stdout)

        # Count the number of repositories
        repositories_count = len(repositories)

        return render_template('nexus.html', repositories=repositories, repositories_count=repositories_count)
    else:
        error_message = f"Error executing curl command: {result.stderr}"
        return render_template('nexus.html', error_message=error_message)
        
        

@app.route('/nexus', methods=['POST'])
def create_repository():
    # Nexus credentials
    nexus_username = 'admin'
    nexus_password = 'nexus'

    # Get the repository name from the form input
    repo_name = request.form.get('repo_name')

    # JSON data for creating the repository
    data = f'''
    {{
        "name": "{repo_name}",
        "online": true,
        "storage": {{
            "blobStoreName": "default",
            "strictContentTypeValidation": true,
            "writePolicy": "allow_once"
        }},
        "cleanup": {{
            "policyNames": [
                "string"
            ]
        }},
        "component": {{
            "proprietaryComponents": true
        }},
        "maven": {{
            "versionPolicy": "MIXED",
            "layoutPolicy": "STRICT",
            "contentDisposition": "ATTACHMENT"
        }}
    }}
    '''

    # Execute the curl command to create a repository
    create_command = f'''curl -X 'POST' \
  'http://192.168.192.8:8081/service/rest/v1/repositories/maven/hosted' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -H 'NX-ANTI-CSRF-TOKEN: 0.6467748182939269' \
  -H 'X-Nexus-UI: true' \
  -u {nexus_username}:{nexus_password} \
  -d '{data}' '''
  
    result_create = subprocess.run(create_command, shell=True, capture_output=True, text=True)

    # Check if the create command executed successfully
    if result_create.returncode == 0:
        # Redirect to the /nexus route
        return redirect(url_for('nexus'))
    else:
        error_message = f"Error creating repository: {result_create.stderr}"
        return render_template('nexus.html', error_message=error_message)
        
   
   

@app.route('/nexus', methods=['POST'])
def delete_repository():
    # Nexus credentials
    nexus_username = 'admin'
    nexus_password = 'nexus'

    # Get the repository name to delete from the form input
    repo_name = request.form.get('delete_repo_name')

    # Construct the curl command to delete the repository directly
    delete_command = f'''curl -X 'DELETE' \
  'http://192.168.192.8:8081/service/rest/v1/repositories/{repo_name}' \
  -H 'NX-ANTI-CSRF-TOKEN: 0.6467748182939269' \
  -u admin:nexus'''

    print("Delete Command:", delete_command)  # Debug output

    # Execute the curl command
    result_delete = subprocess.run(delete_command, shell=True, capture_output=True, text=True)

    # Debugging output
    print("Delete Command Return Code:", result_delete.returncode)
    print("Delete Command Output:", result_delete.stdout)
    print("Delete Command Error:", result_delete.stderr)

    # Check if the delete command executed successfully
    if result_delete.returncode == 0:
        result_text = result_delete.stdout  # Capture the output
        flash(f'Repository deleted successfully. Result: {result_text}', 'success')
    else:
        error_message = f'Error deleting repository: {result_delete.stderr}'
        print(error_message)  # Debug output
        flash(error_message, 'error')

    # Reload the Nexus page to show updated repository list and messages
    return redirect(url_for('create_repository'))







# KUBERNETES CONFIGGGGGGGGGGGGGGGGGGGGGG #
#########################################################################################



@app.route('/nodes')
def get_nodes():
    try:
        # Get Kubernetes API client
        v1 = client.CoreV1Api()

        # Retrieve all nodes
        nodes = v1.list_node()

        # Extract relevant information from nodes
        node_info = []
        for node in nodes.items:
            # Check if the node has the role label
            role_label = node.metadata.labels.get('node-role.kubernetes.io/master', 'Master')  # Assuming a label for the role
            node_info.append({
                'name': node.metadata.name,
                'role': role_label,
                'status': node.status.phase,
            })

        # Retrieve all pods
        pods = v1.list_pod_for_all_namespaces()

        # Extract relevant information from pods
        pod_info = []
        for pod in pods.items:
            pod_info.append({
                'name': pod.metadata.name,
                'namespace': pod.metadata.namespace,
                'labels': pod.metadata.labels,
                'status': pod.status.phase,
            })

        # Retrieve all Persistent Volumes (PVs)
        pvs = v1.list_persistent_volume()

        # Extract relevant information from PVs
        pv_info = []
        for pv in pvs.items:
            pv_info.append({
                'name': pv.metadata.name,
                'capacity': pv.spec.capacity['storage'],
                'access_modes': pv.spec.access_modes,
                'status': pv.status.phase,
            })

        # Retrieve all Persistent Volume Claims (PVCs)
        pvcs = v1.list_persistent_volume_claim_for_all_namespaces()

        # Extract relevant information from PVCs
        pvc_info = []
        for pvc in pvcs.items:
            pvc_info.append({
                'name': pvc.metadata.name,
                'namespace': pvc.metadata.namespace,
                'labels': pvc.metadata.labels,
                'status': pvc.status.phase,
            })

        # Retrieve all Services
        services = v1.list_service_for_all_namespaces()

        # Extract relevant information from Services
        service_info = []
        for service in services.items:
            service_info.append({
                'name': service.metadata.name,
                'namespace': service.metadata.namespace,
                'labels': service.metadata.labels,
                'type': service.spec.type,
                'cluster_ip': service.spec.cluster_ip,
            })

        # Render a template with node, pod, PV, PVC, and Service information
        return render_template('nodes.html', nodes=node_info, pods=pod_info, pvs=pv_info, pvcs=pvc_info, services=service_info)
    except Exception as e:
        error_message = f"Error retrieving data: {str(e)}"
        return render_template('nodes.html', error_message=error_message)
        
        
        

@app.route('/create_deployment', methods=['POST'])
def create_deployment():
    try:
        # Get form data
        deployment_name = request.form.get('deployment_name')
        image = request.form.get('image')  # This will contain the selected Docker image
        replicas = int(request.form.get('replicas'))

        # Get Kubernetes API client for deployments
        apps_v1 = client.AppsV1Api()

        # Define deployment spec
        deployment_manifest = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": deployment_name,
            },
            "spec": {
                "replicas": replicas,
                "selector": {
                    "matchLabels": {"app": deployment_name},
                },
                "template": {
                    "metadata": {
                        "labels": {"app": deployment_name},
                    },
                    "spec": {
                        "containers": [{
                            "name": deployment_name,
                            "image": image,  # Use the selected image here
                            "ports": [{"containerPort": 80}],
                        }],
                    },
                },
            },
        }

        # Create the deployment
        apps_v1.create_namespaced_deployment(namespace="default", body=deployment_manifest)

        flash(f"Deployment '{deployment_name}' created successfully!", "success")

        # Redirect to the route for displaying deployments
        return redirect(url_for('list_deployments'))
    except Exception as e:
        error_message = f"Error creating deployment: {str(e)}"
        flash(error_message, "danger")
        return render_template('create_deployment.html', error_message=error_message)


@app.route('/created', methods=['GET', 'POST'])
def list_deployments():
    try:
        # Load Kubernetes configuration
        config.load_kube_config()

        # Get Kubernetes API client for deployments
        apps_v1 = client.AppsV1Api()

        # Retrieve all deployments
        deployments = apps_v1.list_deployment_for_all_namespaces().items

        # Extract relevant information from deployments
        deployment_info = []
        for deployment in deployments:
            deployment_info.append({
                'name': deployment.metadata.name,
                'namespace': deployment.metadata.namespace,
                'replicas': deployment.spec.replicas,
                'available_replicas': deployment.status.available_replicas,
                'ready_replicas': deployment.status.ready_replicas,
            })

        # Render a template with deployment information
        return render_template('created.html', deployments=deployment_info)
    except Exception as e:
        error_message = f"Error retrieving deployments: {str(e)}"
        return render_template('created.html', error_message=error_message)



@app.route('/delete_deployment', methods=['POST'])
def delete_deployment():
    try:
        deployment_name = request.form.get('deployment_name')

        # Get Kubernetes API client for deployments
        apps_v1 = client.AppsV1Api()

        # Delete the deployment
        apps_v1.delete_namespaced_deployment(name=deployment_name, namespace="default")

        flash(f"Deployment '{deployment_name}' deleted successfully!", "success")

        # Redirect to the same page where deployments are displayed
        return redirect(url_for('list_deployments'))  # Redirect to the route for displaying deployments
    except Exception as e:
        error_message = f"Error deleting deployment: {str(e)}"
        flash(error_message, "danger")
        return render_template('delete_deployment.html', error_message=error_message)  

@app.route('/create_namespace', methods=['POST'])
def create_namespace():
    try:
        # Get form data
        namespace_name = request.form.get('namespace_name')

        # Get Kubernetes API client for namespaces
        v1 = client.CoreV1Api()

        # Define namespace spec
        namespace_manifest = client.V1Namespace(metadata=client.V1ObjectMeta(name=namespace_name))

        # Create the namespace
        v1.create_namespace(body=namespace_manifest)

        # Flash success message
        flash(f"Namespace '{namespace_name}' created successfully!", "success")

        # Redirect to another page or render a template
        return redirect(url_for('list_namespaces'))  # Assuming 'namespaces' is the route to display namespaces
    except Exception as e:
        error_message = f"Error creating namespace: {str(e)}"
        return render_template('create_namespace.html', error_message=error_message)


@app.route('/create_namespace')
def list_namespaces():
    try:
        # Get Kubernetes API client for namespaces
        v1 = client.CoreV1Api()

        # Get list of namespaces
        namespaces = v1.list_namespace().items

        # Render the template with the namespaces data
        return render_template('create_namespace.html', namespaces=namespaces)
    except Exception as e:
        error_message = f"Error fetching namespaces: {str(e)}"
        return render_template('create_namespace.html', error_message=error_message)



###########################################################
#GIIIIIIIIIIIIIT
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username = request.form['username']
        token = request.form['token']
        return redirect(url_for('user_repos', username=username, token=token))
    return render_template('index.html')

@app.route('/repos/<username>', methods=['GET', 'POST'])
def user_repos(username):
    token = request.args.get('token')
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    if request.method == 'POST':
        if 'create_repo' in request.form:
            repo_name = request.form['repo_name']

            data = {
                "name": repo_name,
                "description": "My new repository created using the GitHub API",
                "private": False,
                "auto_init": True
            }

            response = requests.post(f"https://api.github.com/user/repos", headers=headers, data=json.dumps(data))

            if response.status_code == 201:
                message = "Repository created successfully!"
            else:
                message = f"Failed to create repository. Status code: {response.status_code}, Response: {response.json()}"

            return redirect(url_for('user_repos', username=username, token=token, message=message))

        elif 'delete_repo' in request.form:
            repo_name = request.form['delete_repo_name']

            response = requests.delete(f"https://api.github.com/repos/{username}/{repo_name}", headers=headers)

            if response.status_code == 204:
                message = "Repository deleted successfully!"
            else:
                message = f"Failed to delete repository. Status code: {response.status_code}, Response: {response.json()}"

            return redirect(url_for('user_repos', username=username, token=token, message=message))

    # Get user's repositories
    response = requests.get(f"https://api.github.com/users/{username}/repos", headers=headers)
    if response.status_code == 200:
        repos = response.json()
    else:
        repos = []
    
    message = request.args.get('message')
    return render_template('user_repos.html', username=username, token=token, repos=repos, message=message)

@app.route('/repo/<username>/<repo_name>/contents/<path:folder_path>')
def view_repo_contents(username, repo_name, folder_path):
    token = request.args.get('token')
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    # Make GET request to fetch repository contents
    response = requests.get(f"https://api.github.com/repos/{username}/{repo_name}/contents/{folder_path}", headers=headers)

    if response.status_code == 200:
        contents = response.json()
    else:
        contents = []

    return render_template('repo_contents.html', username=username, token=token, repo_name=repo_name, contents=contents)


@app.route('/repo/<username>/<repo_name>/file/<path:file_path>')
def view_file_content(username, repo_name, file_path):
    token = request.args.get('token')
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    # Make GET request to fetch file content
    api_url = f"https://api.github.com/repos/{username}/{repo_name}/contents/{file_path}"
    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        file_content = response.json().get('content')
        # Decode the base64-encoded content
        decoded_content = base64.b64decode(file_content).decode('utf-8')
    else:
        decoded_content = "File content not available."

    return render_template('file_content.html', username=username, repo_name=repo_name, file_path=file_path, content=decoded_content)


@app.route('/repo/<username>/<repo_name>/tree')
def view_repo_tree(username, repo_name):
    token = request.args.get('token')
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    # Make GET request to fetch repository tree
    api_url = f"https://api.github.com/repos/{username}/{repo_name}/git/trees/main?recursive=1"  # Use 'main' or 'master' for the branch name
    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        tree_data = response.json()
    else:
        tree_data = {}

    return render_template('repo_tree.html', username=username, token=token, repo_name=repo_name, tree_data=tree_data)


@app.route('/repo/<username>/<repo_name>/file/<path:file_path>', methods=['GET', 'POST'])
def view_and_edit_file(username, repo_name, file_path):
    if request.method == 'GET':
        token = request.args.get('token')
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json"
        }

        # Make GET request to fetch file content
        api_url = f"https://api.github.com/repos/{username}/{repo_name}/contents/{file_path}"
        response = requests.get(api_url, headers=headers)

        if response.status_code == 200:
            file_content = response.json().get('content')
            # Decode the base64-encoded content
            decoded_content = base64.b64decode(file_content).decode('utf-8')
        else:
            decoded_content = "File content not available."

        return render_template('file_content.html', username=username, repo_name=repo_name, file_path=file_path, content=decoded_content)
    elif request.method == 'POST':
        token = request.form.get('token')
        new_content = request.form.get('new_content')

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json"
        }

        # Get the latest file SHA
        api_url = f"https://api.github.com/repos/{username}/{repo_name}/contents/{file_path}"
        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            latest_sha = response.json().get('sha')

            # Encode new content to base64
            new_content_encoded = base64.b64encode(new_content.encode('utf-8')).decode('utf-8')

            # Make PUT request to update file content
            update_data = {
                "message": "Update file via API",
                "content": new_content_encoded,
                "sha": latest_sha
            }
            update_url = f"https://api.github.com/repos/{username}/{repo_name}/contents/{file_path}"
            update_response = requests.put(update_url, headers=headers, json=update_data)

            if update_response.status_code == 200:
                return redirect(url_for('view_and_edit_file', username=username, repo_name=repo_name, file_path=file_path, token=token))
            else:
                return "Error updating file content."
        else:
            return "Error fetching latest file SHA."


    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    


############## DOCKEEEEEER 


# Initialize Docker client
docker_client = docker.from_env()

@app.route('/docker/images')
def get_docker_images():
    images = docker_client.images.list()
    image_info = [{'id': image.id, 'tags': image.tags} for image in images]
    return render_template('docker_images.html', images=image_info)


@app.route('/docker/containers')
def get_docker_containers():
    containers = docker_client.containers.list()
    container_info = [{'id': container.id, 'name': container.name} for container in containers]
    return render_template('docker_containers.html', containers=container_info)

@app.route('/docker/processes')
def get_docker_processes():
    processes = docker_client.containers.list(all=True)
    process_info = [{'id': process.id, 'name': process.name} for process in processes]
    return render_template('docker_processes.html', processes=process_info)

@app.route('/docker/start', methods=['POST'])
def start_docker_container():
    container_name = request.form['container_name']
    try:
        container = docker_client.containers.get(container_name)
        container.start()
        flash(f"Container {container_name} started successfully.", 'success')
    except docker.errors.NotFound:
        flash(f"Container {container_name} not found.", 'error')
    return redirect(url_for('get_docker_processes'))  # Redirect to the homepage or any other page

@app.route('/docker/stop', methods=['POST'])
def stop_docker_container():
    container_id = request.form['container_id']
    try:
        container = docker_client.containers.get(container_id)
        container.stop()
        flash(f"Container {container_id} stopped successfully.", 'success')
    except docker.errors.NotFound:
        flash(f"Container {container_id} not found.", 'error')
    return redirect(url_for('get_docker_processes'))  # Redirect to the homepage or any other page
    
    
@app.route('/docker_management')
def iindex():
    return render_template('docker_management.html')
    
 


############## PROMMMMMMMMMMMMMMMMMMMMMMMMMMMETHEEUS


def get_prometheus_targets(prometheus_url):
    api_url = f"{prometheus_url}/api/v1/targets"
    response = requests.get(api_url)
    if response.status_code == 200:
        data = response.json()
        targets = data['data']['activeTargets']
        return targets
    else:
        return None

@app.route('/prometheus/targets')
def prometheus_targets():
    prometheus_url = "http://192.168.192.8:30000"  # Replace with your Prometheus URL
    targets = get_prometheus_targets(prometheus_url)
    
    return render_template('prometheus_targets.html', targets=targets)
    
   ###########SONAAAAAAAAAAAAR 
    
    

 
import requests
from requests.auth import HTTPBasicAuth

@app.route('/sonarproject')
def sonarproject():
    # SonarQube API endpoint for projects search
    sonarqube_projects_url = 'http://192.168.192.8:9000/api/projects/search'

    # Username and password for basic authentication
    username = 'admin'
    password = 'sonar'

    # Define headers with basic authentication
    auth = HTTPBasicAuth(username, password)

    # Make a GET request to retrieve projects
    response = requests.get(sonarqube_projects_url, auth=auth)

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        projects_data = response.json()
        projects = []
        for project in projects_data['components']:
            # Fetch issues data for each project
            issues_url = f'http://192.168.192.8:9000/api/issues/search?ps=100&projectKeys={project["key"]}&facets=types'
            issues_response = requests.get(issues_url, auth=auth)
            if issues_response.status_code == 200:
                issues_data = issues_response.json()
                projects.append({
                    'key': project['key'],
                    'name': project['name'],
                    'issues_data': issues_data  # Pass the issues data to the project
                })
            else:
                projects.append({
                    'key': project['key'],
                    'name': project['name'],
                    'issues_data': {'error': f'Failed to fetch issues. Status code: {issues_response.status_code}'}
                })
        return render_template('sonarprojects.html', projects=projects)
    else:
        return f'Error: Failed to retrieve projects. Status code: {response.status_code}'



















@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        # Call the function to get jobs count
       
        count_jobs = jobs_count()
        username = session.get('username')

        # Get the number of Docker containers
        containers = docker_client.containers.list()
        containers_count = len(containers)
        
        

        # Get the number of deployments
        try:
            # Load Kubernetes configuration
            config.load_kube_config()

            # Get Kubernetes API client for deployments
            apps_v1 = client.AppsV1Api()

            # Retrieve all deployments
            deployments = apps_v1.list_deployment_for_all_namespaces().items

            # Count the number of deployments
            deployments_count = len(deployments)
        except Exception as e:
            deployments_count = 0  # Handle the case where retrieving deployments fails

        return render_template('dashboard.html', jobs_count=count_jobs, containers_count=containers_count, deployments_count=deployments_count,username=username)
    else:
        return redirect(url_for('login'))











if __name__ == '__main__':
    app.run(debug=True)



# #Create deployment jobs
# #create a blank job
# server.create_job("job1", jenkins.EMPTY_CONFIG_XML)
# #create pre-configured-job
# job2_xml = open("job2.xml", mode='r', encoding='utf-8').read()
# server.create_job("job2", job2_xml)

# job3_xml = open("job3.xml", mode='r', encoding='utf-8').read()
# server.create_job("job3", job3_xml)

#view jobs
# jobs = server.get_jobs()
# print(jobs)

#copy job
# server.copy_job('job2', 'job4')

#update job
# updated_job_3 = open("job_3_updated.xml", mode='r', encoding='utf-8').read()
# server.reconfig_job('job3', updated_job_3)

#disable job
# server.disable_job('sample_job')

# Run a build and get build number and more info
# server.build_job('job3')
# last_build_number = server.get_job_info('job3')['lastCompletedBuild']['number']
# print("Build Number", last_build_number)
# build_info = server.get_build_info('job3', last_build_number)
# print("build info", build_info)

#delete job
# server.delete_job('sample_job')


# Create View
# view_config = open("jobs_view.xml", mode='r', encoding='utf-8').read()
# server.create_view("Job List", view_config)

#get list of view
# views = server.get_views()
# print(views)

# Update View
# updated_view_config = open("jobs_view_updated.xml", mode='r', encoding='utf-8').read()
# server.reconfig_view("Job List", updated_view_config)

#Delete View
# server.delete_view("Job List")
