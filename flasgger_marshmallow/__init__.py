import functools
import logging
import re
from collections import defaultdict

import marshmallow
import yaml
from flasgger.base import Swagger as FSwagger
from flasgger.constants import OPTIONAL_FIELDS
try:
    from flasgger.constants import OPTIONAL_OAS3_FIELDS
except :
    OPTIONAL_OAS3_FIELDS = [
        'components', 'servers'
    ]
from flasgger.utils import extract_definitions
from flasgger.utils import get_specs
from flasgger.utils import get_vendor_extension_fields
from flasgger.utils import parse_definition_docstring
from flask import request
from marshmallow import __version__
from marshmallow import fields
from marshmallow.utils import _Missing

logger = logging.getLogger(__name__)

__all__ = ['Swagger', 'swagger_decorator']

FIELDS_JSON_TYPE_MAP = {
    fields.Nested: 'object',
    fields.Dict: 'object',
    fields.List: 'array',
    fields.String: 'string',
    fields.UUID: 'string',
    fields.Number: 'number',
    fields.Integer: 'number',
    fields.Decimal: 'number',
    fields.Boolean: 'bool',
    fields.Float: 'number',
    fields.DateTime: 'string',
    fields.Time: 'string',
    fields.Date: 'string',
    fields.TimeDelta: 'number',
    fields.Url: 'string',
    fields.URL: 'string',
    fields.Email: 'string',
    fields.Str: 'string',
    fields.Bool: 'bool',
    fields.Int: 'number',
}

if int(marshmallow.__version__.split('.')[0]) == 3:
    FIELDS_JSON_TYPE_MAP.update({
        fields.NaiveDateTime: 'string',
        fields.AwareDateTime: 'string',
        fields.Tuple: 'array',
    })


def is_marsh_v3():
    return int(marshmallow.__version__.split('.')[0]) == 3


def data_schema(schema, data):
    data = schema().load(data or {})
    if not is_marsh_v3():
        data = schema().dump(data.data).data
    else:
        data = schema().dump(data)
    return data


class Swagger(FSwagger):

    def get_apispecs(self, endpoint='apispec_1'):
        if not self.app.debug and endpoint in self.apispecs:
            return self.apispecs[endpoint]

        spec = None
        for _spec in self.config['specs']:
            if _spec['endpoint'] == endpoint:
                spec = _spec
                break
        if not spec:
            raise RuntimeError(
                'Can`t find specs by endpoint {:d},'
                ' check your flasger`s config'.format(endpoint))

        data = {
            # try to get from config['SWAGGER']['info']
            # then config['SWAGGER']['specs'][x]
            # then config['SWAGGER']
            # then default
            "info": self.config.get('info') or {
                "version": spec.get(
                    'version', self.config.get('version', "0.0.1")
                ),
                "title": spec.get(
                    'title', self.config.get('title', "A swagger API")
                ),
                "description": spec.get(
                    'description', self.config.get('description',
                                                   "powered by Flasgger")
                ),
                "termsOfService": spec.get(
                    'termsOfService', self.config.get('termsOfService',
                                                      "/tos")
                ),
            },
            "paths": self.config.get('paths') or defaultdict(dict),
            "definitions": self.config.get('definitions') or defaultdict(dict)
        }

        openapi_version = self.config.get('openapi')
        if openapi_version:
            data["openapi"] = openapi_version
        else:
            data["swagger"] = self.config.get('swagger') or self.config.get(
                'swagger_version', "2.0"
            )

        # Support extension properties in the top level config
        top_level_extension_options = get_vendor_extension_fields(self.config)
        if top_level_extension_options:
            data.update(top_level_extension_options)

        # if True schemaa ids will be prefized by function_method_{id}
        # for backwards compatibility with <= 0.5.14
        prefix_ids = self.config.get('prefix_ids')

        if self.config.get('host'):
            data['host'] = self.config.get('host')
        if self.config.get("basePath"):
            data["basePath"] = self.config.get('basePath')
        if self.config.get('schemes'):
            data['schemes'] = self.config.get('schemes')
        if self.config.get("securityDefinitions"):
            data["securityDefinitions"] = self.config.get(
                'securityDefinitions'
            )

        def is_openapi3():
            """
            Returns True if openapi_version is 3
            """
            return openapi_version and openapi_version.split('.')[0] == '3'

        if is_openapi3():
            # enable oas3 fields when openapi_version is 3.*.*
            optional_oas3_fields = self.config.get(
                'optional_oas3_fields') or OPTIONAL_OAS3_FIELDS
            for key in optional_oas3_fields:
                if self.config.get(key):
                    data[key] = self.config.get(key)

        # set defaults from template
        if self.template is not None:
            data.update(self.template)

        paths = data['paths']
        definitions = data['definitions']
        ignore_verbs = set(
            self.config.get('ignore_verbs', ("HEAD", "OPTIONS"))
        )

        # technically only responses is non-optional
        optional_fields = self.config.get('optional_fields') or OPTIONAL_FIELDS

        for name, def_model in self.get_def_models(
                spec.get('definition_filter')).items():
            description, swag = parse_definition_docstring(
                def_model, self.sanitizer)
            if name and swag:
                if description:
                    swag.update({'description': description})
                definitions[name].update(swag)

        specs = get_specs(
            self.get_url_mappings(spec.get('rule_filter')), ignore_verbs,
            optional_fields, self.sanitizer,
            doc_dir=self.config.get('doc_dir'))

        http_methods = ['get', 'post', 'put', 'delete']
        for rule, verbs in specs:
            operations = dict()
            for verb, swag in verbs:
                update_dict = swag.get('definitions', {})
                if type(update_dict) == list and type(update_dict[0]) == dict:
                    # pop, assert single element
                    update_dict, = update_dict
                definitions.update(update_dict)
                defs = []  # swag.get('definitions', [])
                defs += extract_definitions(
                    defs, endpoint=rule.endpoint, verb=verb,
                    prefix_ids=prefix_ids
                )

                params = swag.get('parameters', [])
                if verb in swag.keys():
                    verb_swag = swag.get(verb)
                    if len(params) == 0 and verb.lower() in http_methods:
                        params = verb_swag.get('parameters', [])

                defs += extract_definitions(params,
                                            endpoint=rule.endpoint,
                                            verb=verb,
                                            prefix_ids=prefix_ids)

                request_body = swag.get('requestBody')
                if request_body:
                    content = request_body.get("content", {})
                    extract_definitions(
                        list(content.values()),
                        endpoint=rule.endpoint,
                        verb=verb,
                        prefix_ids=prefix_ids
                    )

                callbacks = swag.get("callbacks", {})
                if callbacks:
                    callbacks = {
                        str(key): value
                        for key, value in callbacks.items()
                    }
                    extract_definitions(
                        list(callbacks.values()),
                        endpoint=rule.endpoint,
                        verb=verb,
                        prefix_ids=prefix_ids
                    )

                responses = None
                if 'responses' in swag:
                    responses = swag.get('responses', {})
                    responses = {
                        str(key): value
                        for key, value in responses.items()
                    }
                    if responses is not None:
                        defs = defs + extract_definitions(
                            responses.values(),
                            endpoint=rule.endpoint,
                            verb=verb,
                            prefix_ids=prefix_ids
                        )
                    for definition in defs:
                        if 'id' not in definition:
                            definitions.update(definition)
                            continue
                        def_id = definition.pop('id')
                        if def_id is not None:
                            definitions[def_id].update(definition)

                operation = {}
                if swag.get('summary'):
                    operation['summary'] = swag.get('summary')
                if swag.get('description'):
                    operation['description'] = swag.get('description')
                if request_body:
                    operation['requestBody'] = request_body
                if callbacks:
                    operation['callbacks'] = callbacks
                if responses:
                    operation['responses'] = responses
                # parameters - swagger ui dislikes empty parameter lists
                if len(params) > 0:
                    operation['parameters'] = params
                # other optionals
                for key in optional_fields:
                    if key in swag:
                        value = swag.get(key)
                        if key in ('produces', 'consumes'):
                            if not isinstance(value, (list, tuple)):
                                value = [value]

                        operation[key] = value
                operations[verb] = operation

            if len(operations):
                prefix = data.get('swaggerUiPrefix') or ''
                srule = '{0}{1}'.format(prefix, rule)
                # handle basePath
                base_path = data.get('basePath')

                if base_path:
                    if base_path.endswith('/'):
                        base_path = base_path[:-1]
                    if base_path:
                        # suppress base_path from srule if needed.
                        # Otherwise we will get definitions twice...
                        if srule.startswith(base_path):
                            srule = srule[len(base_path):]

                # old regex '(<(.*?\:)?(.*?)>)'
                for arg in re.findall('(<([^<>]*:)?([^<>]*)>)', srule):
                    srule = srule.replace(arg[0], '{%s}' % arg[2])

                for key, val in operations.items():
                    if srule not in paths:
                        paths[srule] = {}
                    if key in paths[srule]:
                        paths[srule][key].update(val)
                    else:
                        paths[srule][key] = val
        self.apispecs[endpoint] = data
        return data


def unpack(value):
    """Return a three tuple of data, code, and headers"""
    if not isinstance(value, tuple):
        return value, 200, {}

    try:
        data, code, headers = value
        return data, code, headers
    except ValueError:
        pass

    try:
        data, code = value
        return data, code, {}
    except ValueError:
        pass

    return value, 200, {}


def swagger_decorator(
        path_schema=None, query_schema=None,
        form_schema=None, json_schema=None,
        headers_schema=None, response_schema=None,
        tags=None
):
    def decorator(func):

        def parse_simple_schema(c_schema, location):
            ret = []
            for key, value in c_schema.__dict__.get('_declared_fields').items():
                values_real_types = list(set(FIELDS_JSON_TYPE_MAP) & set(value.__class__.__mro__))
                values_real_types.sort(key=value.__class__.__mro__.index)
                if not values_real_types:
                    raise '不支持的%s类型' % str(type(value))
                if is_marsh_v3():
                    name = getattr(value, 'data_key', None) or key
                else:
                    name = getattr(value, 'load_from', None) or key
                tmp = {
                    'in': location,
                    'name': name,
                    'type': FIELDS_JSON_TYPE_MAP.get(values_real_types[0]),
                    'required': value.required if location != 'path' else True,
                    'description': value.metadata.get('doc', '')
                }
                if not isinstance(value.default, _Missing):
                    tmp['default'] = value.default
                ret.append(tmp)
            return ret

        def parse_json_schema(r_s):
            tmp = {}
            for key, value in (
                    r_s.__dict__.get('_declared_fields') or r_s.__dict__.get('declared_fields') or {}).items():
                if is_marsh_v3():
                    key = getattr(value, 'data_key', None) or key
                else:
                    key = getattr(value, 'load_from', None) or key
                if isinstance(value, fields.Nested):
                    if value.many:
                        tmp[key] = {
                            'type': 'array',
                            'description': value.metadata.get('doc', ''),
                            'items': {
                                'type': 'object',
                                'properties': parse_json_schema(value.schema),
                            }
                        }
                    else:
                        tmp[key] = {
                            'type': 'object',
                            'properties': parse_json_schema(value.schema)
                        }
                elif isinstance(value, fields.List):
                    tmp[key] = {
                        'type': 'array',
                        'description': value.metadata.get('doc', ''),
                        'items': {
                            'type': 'string',
                        }
                    }
                    if not isinstance(value.default, _Missing):
                        tmp[key]['default'] = value.default
                else:
                    values_real_types = list(set(FIELDS_JSON_TYPE_MAP) & set(value.__class__.__mro__))
                    values_real_types.sort(key=value.__class__.__mro__.index)
                    if not values_real_types:
                        raise '不支持的%s类型' % str(type(value))
                    tmp[key] = {
                        'type': FIELDS_JSON_TYPE_MAP.get(values_real_types[0]),
                        'description': value.metadata.get('doc', ''),
                        'required': value.required,
                    }
                    if not isinstance(value.default, _Missing):
                        tmp[key]['default'] = value.default
            return tmp

        def parse_request_body_json_schema(c_schema):
            tmp = {
                'in': 'body',
                'name': 'body',
                'required': True,
                'description': 'json 类型的body',
                'schema': {
                    'properties': parse_json_schema(c_schema),
                    'type': 'object',
                }
            }
            return [tmp]

        def generate_doc():
            doc_dict = {}
            if path_schema or query_schema or form_schema or json_schema or headers_schema:
                doc_dict['parameters'] = []
            if path_schema:
                doc_dict['parameters'].extend(parse_simple_schema(path_schema, 'path'))
            if query_schema:
                doc_dict['parameters'].extend(parse_simple_schema(query_schema, 'query'))
            if form_schema:
                doc_dict['parameters'].extend(parse_simple_schema(form_schema, 'formData'))
            if headers_schema:
                doc_dict['parameters'].extend(parse_simple_schema(headers_schema, 'header'))
            if json_schema:
                doc_dict['parameters'].extend(parse_request_body_json_schema(json_schema))
            if response_schema:
                doc_dict['responses'] = {}
                for code, current_schema in response_schema.items():
                    doc_dict['responses'][code] = {
                        'description': current_schema.__doc__,
                        'schema': {
                            'type': 'object',
                            "properties": parse_json_schema(current_schema),
                        },
                    }
                    if not doc_dict['responses'][code].get('schema', {}).get('properties'):
                        doc_dict['responses'][code].update({'schema': None})
                    if getattr(current_schema.Meta, 'headers', None):
                        doc_dict['responses'][code].update(
                            {'headers': parse_json_schema(current_schema.Meta.headers)}
                        )
                    produces = getattr(current_schema.Meta, 'produces', None)
                    if produces:
                        doc_dict.setdefault('produces', [])
                        doc_dict['produces'].extend(produces)
                        'application/xml' in produces and doc_dict['responses'][code]['schema'] and \
                        doc_dict['responses'][code]['schema'].update(
                            {'xml': {'name': getattr(current_schema.Meta, 'xml_root', 'xml')}}
                        )
            if tags:
                doc_dict['tags'] = tags

            ret_doc = """---\n""" + yaml.dump(doc_dict)
            return ret_doc

        func.__doc__ = (func.__doc__.strip() + generate_doc()) if func.__doc__ else generate_doc()

        @functools.wraps(func)
        def wrapper(*args, **kw):
            path_params = request.view_args
            query_params = request.args
            form_params = request.form
            json_params = request.get_json(silent=True) or {}
            header_params = request.headers
            logger.info(
                'request params\npath params: %s\nquery params: %s\nform params: %s\njson params: %s\n',
                path_params, query_params, form_params, json_params
            )
            logger.info('headers: %s\n', header_params)
            request.path_schema, request.path_schema, request.form_schema = [None] * 3
            request.json_schema, request.headers_schema = [None] * 2
            try:
                path_schema and setattr(request, 'path_schema', data_schema(path_schema, path_params))
                query_schema and setattr(request, 'query_schema', data_schema(query_schema, query_params))
                form_schema and setattr(request, 'form_schema', data_schema(form_schema, form_params))
                json_schema and setattr(request, 'json_schema', data_schema(json_schema, json_params))
                headers_schema and setattr(request, 'headers_schema', data_schema(headers_schema, dict(header_params)))
            except Exception as e:
                return 'request error: %s' % ''.join(
                    [('%s: %s; ' % (x, ''.join(y))) for x, y in e.messages.items()]), 400
            f_result = func(*args, **kw)
            data, code, headers = unpack(f_result)
            logger.info('response data\ndata: %s\ncode: %s\nheaders: %s\n', data, code, headers)
            try:
                if response_schema and response_schema.get(code):
                    data = data_schema(response_schema.get(code), data)
                    r_headers_schema = getattr(response_schema.get(code).Meta, 'headers', None)
                    if r_headers_schema:
                        headers = data_schema(r_headers_schema, headers)
            except Exception as e:
                return 'response error: %s' % ''.join(
                    [('%s: %s; ' % (x, ''.join(y))) for x, y in e.messages.items()]), 400
            return data, code, headers

        return wrapper

    return decorator
