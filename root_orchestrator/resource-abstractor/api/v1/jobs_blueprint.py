import json

from bson.objectid import ObjectId
from db import jobs_db
from db.jobs_helper import build_filter
from flask import request
from flask.views import MethodView
from flask_smorest import Blueprint
from marshmallow import Schema, fields
from services.hook_service import perform_create, perform_update, pre_post_hook
from werkzeug import exceptions

jobsblp = Blueprint("Jobs", "jobs", url_prefix="/api/v1/jobs")


class JobFilterSchema(Schema):
    instance_number = fields.Integer()


@jobsblp.route("/")
class AllJobsController(MethodView):
    def get(self):
        appID = request.args.get("applicationID")
        filter = {}
        if appID:
            filter["applicationID"] = appID
        return json.dumps(list(jobs_db.find_jobs(filter)), default=str)

    @pre_post_hook("jobs")
    def post(self, data, *args, **kwargs):
        result = jobs_db.create_job(data)
        return json.dumps(result, default=str)

    def put(self, *args, **kwargs):
        job_data = request.json
        job_name = job_data.get("job_name")
        job = jobs_db.find_job_by_name(job_name)

        res = None
        if job:
            res = perform_update("job", jobs_db.update_job, str(job.get("_id")), job_data)
        else:
            res = perform_create("job", jobs_db.create_job, job_data)

        return json.dumps(res, default=str)


@jobsblp.route("/<job_id>")
class JobController(MethodView):
    @jobsblp.arguments(JobFilterSchema, location="query")
    def get(self, query, **kwargs):
        job_id = kwargs.get("job_id")
        if ObjectId.is_valid(job_id) is False:
            raise exceptions.BadRequest()

        filter = build_filter(query)
        job = jobs_db.find_job_by_id(job_id, filter)
        if job is None:
            raise exceptions.NotFound()

        return json.dumps(job, default=str)

    @pre_post_hook("jobs", with_param_id="job_id")
    def patch(self, data, *args, **kwargs):
        job_id = kwargs.get("job_id")
        result = jobs_db.update_job(job_id, data)

        return json.dumps(result, default=str)

    @pre_post_hook("jobs", with_param_id="job_id")
    def delete(self, *args, **kwargs):
        job_id = kwargs.get("job_id")
        result = jobs_db.delete_job(job_id)

        return json.dumps(result, default=str)


@jobsblp.route("/<job_id>/<instance_id>")
class JobInstanceController(MethodView):
    @pre_post_hook("jobs", with_param_id="job_id")
    def patch(self, data, *args, **kwargs):
        data = request.json
        job_id = kwargs.get("job_id")
        instance_id = kwargs.get("instance_id")
        if ObjectId.is_valid(job_id) is False:
            raise exceptions.BadRequest()

        result = jobs_db.update_job_instance(job_id, instance_id, data)
        if result is None:
            raise exceptions.NotFound()

        return json.dumps(result, default=str)
