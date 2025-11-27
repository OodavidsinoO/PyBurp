def fixed_content_length(request):
    if request.body().length() != 0:
        return request.withHeader("Content-Length", str(request.body().length()))
    return request


def handleRequest(request, annotations):
    return fixed_content_length(httpRequest(request.httpService(),request.toString().replace('randomplz',randomstring(8)))), annotations

