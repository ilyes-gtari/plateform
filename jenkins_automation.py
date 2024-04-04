from flask import Flask, render_template, request, redirect, url_for, flash
import jenkins
import nexus_api
import subprocess
import json


app = Flask(__name__)
'''

# Jenkins server configuration
host = "https://fa59-197-27-117-30.ngrok-free.app"
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

@app.route('/')
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

'''




@app.route('/')
def nexus():
    # Execute the curl command to retrieve repositories from the Nexus server
    command = 'curl -X GET https://75ea-197-27-117-30.ngrok-free.app/service/rest/v1/repositories'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    # Check if the command executed successfully and return the result directly
    if result.returncode == 0:
        repositories = json.loads(result.stdout)
        return render_template('nexus.html', repositories=repositories)
    else:
        error_message = f"Error executing curl command: {result.stderr}"
        return render_template('nexus.html', error_message=error_message)

@app.route('/', methods=['POST'])
def create_repository():
    # Nexus credentials
    nexus_username = 'admin'
    nexus_password = 'nexus'

    # Execute the curl command to create a repository with Nexus authentication
    command = f'''curl -X 'POST' \
  'https://75ea-197-27-117-30.ngrok-free.app/service/rest/v1/repositories/maven/hosted' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -u {nexus_username}:{nexus_password} \
  -d '{
  "name": "internal",
  "online": true,
  "storage": {
    "blobStoreName": "default",
    "strictContentTypeValidation": true,
    "writePolicy": "allow_once"
  },
  "cleanup": {
    "policyNames": [
      "string"
    ]
  },
  "component": {
    "proprietaryComponents": true
  },
  "maven": {
    "versionPolicy": "MIXED",
    "layoutPolicy": "STRICT",
    "contentDisposition": "ATTACHMENT"
  }
}' '''
    result = subprocess.run(command, shell=True, capture_output=True, text=True)

    # Check if the command executed successfully and return the result
    if result.returncode == 0:
        response = json.loads(result.stdout)
        return render_template('nexus.html', response=response)

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