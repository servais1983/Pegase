{{- define "pegase.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "pegase.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "pegase.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "pegase.labels" -}}
app.kubernetes.io/name: {{ include "pegase.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

{{- define "pegase.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pegase.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
