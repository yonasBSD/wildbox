"""
Core Views - Health checks and system endpoints

The Guardian: Proactive Vulnerability Management
"""

import json
import psutil
from django.http import JsonResponse, HttpResponse
from django.views import View
from django.conf import settings
from django.db import connection
from django.core.cache import cache
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from apps.core.models import SystemConfiguration
import redis


class HealthCheckView(APIView):
    """Health check endpoint for monitoring."""
    
    authentication_classes = []
    permission_classes = []
    
    def get(self, request):
        """Return system health status."""
        health_data = {
            'status': 'healthy',
            'timestamp': timezone.now().isoformat(),
            'checks': {}
        }
        
        # Database check
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            health_data['checks']['database'] = {'status': 'healthy'}
        except Exception as e:
            health_data['checks']['database'] = {
                'status': 'unhealthy'
            }
            health_data['status'] = 'unhealthy'
        
        # Redis check
        try:
            cache.set('health_check', 'ok', 10)
            cache.get('health_check')
            health_data['checks']['redis'] = {'status': 'healthy'}
        except Exception as e:
            health_data['checks']['redis'] = {
                'status': 'unhealthy'
            }
            health_data['status'] = 'unhealthy'
        
        response_status = status.HTTP_200_OK if health_data['status'] == 'healthy' else status.HTTP_503_SERVICE_UNAVAILABLE
        return Response(health_data, status=response_status)


class MetricsView(View):
    """Prometheus metrics endpoint."""
    
    def get(self, request):
        """Return Prometheus metrics."""
        if not settings.PROMETHEUS_ENABLED:
            return HttpResponse("Metrics disabled", status=404)
        
        try:
            from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
            return HttpResponse(generate_latest(), content_type=CONTENT_TYPE_LATEST)
        except ImportError:
            return HttpResponse("Prometheus client not available", status=503)


class SystemInfoView(APIView):
    """System information endpoint."""
    
    def get(self, request):
        """Return system information."""
        system_info = {
            'application': {
                'name': 'Open Security Guardian',
                'description': 'Proactive Vulnerability Management Platform'
            }
        }

        return Response(system_info)


# Import required modules for system info
import sys
import platform
import django
from django.utils import timezone
