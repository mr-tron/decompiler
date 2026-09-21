"""Public, structured errors; never expose compiler filesystem paths in HTTP."""


class DecompilerError(Exception):
    def __init__(self, code, message, stage, status=422, diagnostics=None):
        super().__init__(message)
        self.code, self.stage, self.status = code, stage, status
        self.diagnostics = diagnostics or []

    def response(self):
        return {'success': False, 'error': {'code': self.code, 'message': str(self),
                'stage': self.stage}, 'diagnostics': self.diagnostics}
