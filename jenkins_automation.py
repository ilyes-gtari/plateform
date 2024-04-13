from flask import Flask, render_template, request, redirect, url_for, flash
from kubernetes import client, config
import jenkins
import subprocess
import json
import git
import requests
import base64


app = Flask(__name__)
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
        return render_template('nexus.html', repositories=repositories)
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
        # Execute the curl command to retrieve repositories from the Nexus server
        retrieve_command = f'curl -X GET http://192.168.192.8:8081/service/rest/v1/repositories -u {nexus_username}:{nexus_password}'
        result_retrieve = subprocess.run(retrieve_command, shell=True, capture_output=True, text=True)
        
        # Check if the retrieve command executed successfully
        if result_retrieve.returncode == 0:
            repositories = json.loads(result_retrieve.stdout)
            return render_template('nexus.html', response=repositories)
        else:
            error_message = f"Error retrieving repositories: {result_retrieve.stderr}"
            return render_template('nexus.html', error_message=error_message)
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

@app.route('/git')
def get_git_repos():
    try:
        # GitHub API endpoint for fetching user repositories
        url = 'https://api.github.com/user/repos'
        # Token for authorization
        token = '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'
        headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json'
        }

        # Send GET request to GitHub API
        response = requests.get(url, headers=headers)

        # Check if request was successful
        if response.status_code == 200:
            # Extract repository names from JSON response
            repos = [repo['name'] for repo in response.json()]
            return render_template('git_repos.html', repos=repos)
        else:
            # Handle API request error
            error_message = f"Error fetching repositories: {response.status_code}"
            return render_template('git_repos.html', error_message=error_message)
    except Exception as e:
        # Handle general exception
        error_message = f"Error: {str(e)}"
        return render_template('git_repos.html', error_message=error_message)







@app.route('/repo_content/<repo_name>', methods=['GET'])
def show_repo_content(repo_name):
    try:
        # GitHub API endpoint for fetching repository content
        url = f'https://api.github.com/repos/ilyes-gtari/{repo_name}/contents/'
        # Token for authorization
        token = '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'
        headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/vnd.github.v3+json'
        }

        # Send GET request to GitHub API
        response = requests.get(url, headers=headers)

        # Check if request was successful
        if response.status_code == 200:
            # Extract repository content from JSON response
            content = response.json()
            return render_template('repo_content.html', repo_name=repo_name, content=content)
        else:
            # Handle API request error
            error_message = f"Error fetching content of repository '{repo_name}': {response.status_code}"
            return render_template('git_repos.html', error_message=error_message)
    except Exception as e:
        # Handle general exception
        error_message = f"Error: {str(e)}"
        return render_template('git_repos.html', error_message=error_message)
        
        
        
        
@app.route('/repo_file/<repo_name>/<file_name>', methods=['GET'])
def show_repo_file(repo_name, file_name):
    try:
        # GitHub API endpoint for fetching specific file content
        url = f'https://api.github.com/repos/ilyes-gtari/{repo_name}/contents/{file_name}'
        # Token for authorization
        token = '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'
        headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/vnd.github.v3+json'
        }

        # Send GET request to GitHub API
        response = requests.get(url, headers=headers)

        # Check if request was successful
        if response.status_code == 200:
            # Extract file content from JSON response
            file_content = base64.b64decode(response.json()['content']).decode('utf-8')
            return render_template('repo_file_content.html', repo_name=repo_name, file_name=file_name, file_content=file_content)
        else:
            # Handle API request error
            error_message = f"Error fetching content of file '{file_name}' in repository '{repo_name}': {response.status_code}"
            return render_template('git_repos.html', error_message=error_message)
    except Exception as e:
        # Handle general exception
        error_message = f"Error: {str(e)}"
        return render_template('git_repos.html', error_message=error_message)
        
        

@app.route('/repo_content/<repo_name>/<path:folder_path>', methods=['GET'])
def show_repo_folder(repo_name, folder_path):
    try:
        # GitHub API endpoint for fetching folder content
        url = f'https://api.github.com/repos/ilyes-gtari/{repo_name}/contents/{folder_path}'
        # Token for authorization
        token = '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'
        headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/vnd.github.v3+json'
        }

        # Send GET request to GitHub API
        response = requests.get(url, headers=headers)

        # Check if request was successful
        if response.status_code == 200:
            # Extract folder content from JSON response
            content = response.json()
            return render_template('repo_content.html', repo_name=repo_name, content=content)
        else:
            # Handle API request error
            error_message = f"Error fetching content of folder '{folder_path}' in repository '{repo_name}': {response.status_code}"
            return render_template('git_repos.html', error_message=error_message)
    except Exception as e:
        # Handle general exception
        error_message = f"Error: {str(e)}"
        return render_template('git_repos.html', error_message=error_message)
        
        
        
        




@app.route('/create_repo', methods=['POST'])
def create_repo():
    repo_name = request.form['repo_name']
    token = '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'
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    data = {'name': repo_name}
    response = requests.post('https://api.github.com/user/repos', headers=headers, json=data)
    if response.status_code == 201:
        flash(f'Repository "{repo_name}" created successfully!', 'success')
        return redirect(url_for('get_git_repos'))  # Redirect to another route or page
    else:
        flash(f'Failed to create repository. Status code: {response.status_code}', 'danger')
        return redirect(url_for('get_git_repos'))  # Redirect to another route or page

@app.route('/delete_repo', methods=['POST'])
def delete_repo():
    repo_name = request.form['repo_name']
    token = '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'
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/vnd.github+json'
    }
    delete_url = f'https://api.github.com/repos/ilyes-gtari/{repo_name}'
    response = requests.delete(delete_url, headers=headers)
    if response.status_code == 204:
        flash(f'Repository "{repo_name}" deleted successfully!', 'success')
    else:
        flash(f'Failed to delete repository "{repo_name}". Status code: {response.status_code}', 'danger')
    return redirect(url_for('get_git_repos'))  # Redirect to another route or page









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
