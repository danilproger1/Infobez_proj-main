import { useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Chip,
  Paper,
  Stack,
  TextField,
  Typography,
} from '@mui/material';

const API_BASE = 'http://localhost:8000';

const anomalyLabels = {
  sql_injection: 'Признак SQL-инъекции',
  night_login: 'Ночной вход',
  failed_burst: 'Серия неудачных входов',
  auth_blocked: 'Автоблокировка IP',
  ip_blocked: 'Попытка с заблокированного IP',
  new_ip: 'Новый IP пользователя',
  ip_activity_spike: 'Статистический всплеск по IP',
};

const emptyDashboard = {
  summary: {
    totalEvents: 0,
    suspiciousEvents: 0,
    successfulLogins: 0,
    failedLogins: 0,
    blockedAttempts: 0,
    activeBlocks: 0,
  },
  alerts: [],
  events: [],
  blockedIps: [],
  chart: [],
};

function StatCard({ label, value, accent }) {
  return (
    <Paper className="stat-card" elevation={0}>
      <span className={`stat-dot ${accent}`} />
      <Typography className="stat-label">{label}</Typography>
      <Typography className="stat-value">{value}</Typography>
    </Paper>
  );
}

function ActivityChart({ points }) {
  const safePoints = points.length ? points : emptyDashboard.chart;
  const maxValue = Math.max(
    1,
    ...safePoints.flatMap((point) => [
      point.suspicious ?? 0,
      point.blocked ?? 0,
      point.sqlInjection ?? 0,
    ]),
  );
  const chartHeight = 220;
  const gap = safePoints.length > 1 ? 100 / (safePoints.length - 1) : 100;

  const buildLine = (key) =>
    safePoints
      .map((point, index) => {
        const x = index * gap;
        const y = 100 - (point[key] / maxValue) * 100;
        return `${x},${y}`;
      })
      .join(' ');

  return (
    <div className="chart-shell">
      <div className="chart-grid">
        {[0, 1, 2, 3, 4].map((step) => (
          <span
            key={step}
            className="chart-grid-line"
            style={{ bottom: `${step * 25}%` }}
          />
        ))}
      </div>
      <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="chart-svg">
        <polyline className="line-alert" points={buildLine('suspicious')} />
        <polyline className="line-blocked" points={buildLine('blocked')} />
        <polyline className="line-sql" points={buildLine('sqlInjection')} />
        {safePoints.map((point, index) => {
          const x = index * gap;
          const suspiciousY = 100 - ((point.suspicious ?? 0) / maxValue) * 100;
          const blockedY = 100 - ((point.blocked ?? 0) / maxValue) * 100;
          const sqlInjectionY = 100 - ((point.sqlInjection ?? 0) / maxValue) * 100;
          return (
            <g key={point.label}>
              <circle className="chart-point-alert" cx={x} cy={suspiciousY} r="1.5" />
              <circle className="chart-point-blocked" cx={x} cy={blockedY} r="1.5" />
              <circle className="chart-point-sql" cx={x} cy={sqlInjectionY} r="1.5" />
            </g>
          );
        })}
      </svg>
      <div className="chart-labels" style={{ height: chartHeight }}>
        {safePoints.map((point) => (
          <span key={point.label}>{point.label}</span>
        ))}
      </div>
      <div className="chart-legend">
        <span>
          <i className="legend-mark alert" />
          Подозрительные события
        </span>
        <span>
          <i className="legend-mark blocked" />
          Заблокированные IP
        </span>
        <span>
          <i className="legend-mark sql" />
          SQL-инъекции
        </span>
      </div>
    </div>
  );
}

function LoginForm() {
  const [formData, setFormData] = useState({
    login: 'admin',
    password: 'admin',
    ip: '192.168.1.10',
  });
  const [loading, setLoading] = useState(false);
  const [feedback, setFeedback] = useState(null);
  const [dashboard, setDashboard] = useState(emptyDashboard);

  useEffect(() => {
    const loadDashboard = async () => {
      try {
        const response = await fetch(`${API_BASE}/api/dashboard`);
        if (!response.ok) {
          return;
        }
        const data = await response.json();
        setDashboard(data);
      } catch (error) {
        console.error('Не удалось загрузить панель мониторинга', error);
      }
    };

    loadDashboard();
  }, []);

  const handleChange = (event) => {
    const { name, value } = event.target;
    setFormData((current) => ({ ...current, [name]: value }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setLoading(true);

    try {
      const response = await fetch(`${API_BASE}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });
      const data = await response.json();

      setFeedback({
        severity: data.ok ? 'success' : 'error',
        message: data.message,
        anomalies: data.anomalies ?? [],
      });
      if (data.dashboard) {
        setDashboard(data.dashboard);
      }
    } catch (error) {
      console.error('Ошибка сервера', error);
      setFeedback({
        severity: 'error',
        message: 'Сервер недоступен. Проверь запуск FastAPI на порту 8000.',
        anomalies: [],
      });
    } finally {
      setLoading(false);
    }
  };

  const handleClearHistory = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE}/api/history/clear`, {
        method: 'POST',
      });
      const data = await response.json();
      setDashboard(data.dashboard ?? emptyDashboard);
      setFeedback({
        severity: 'success',
        message: data.message,
        anomalies: [],
      });
    } catch (error) {
      console.error('Не удалось очистить историю', error);
      setFeedback({
        severity: 'error',
        message: 'Не удалось очистить историю логов.',
        anomalies: [],
      });
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadLogs = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/logs/download`);
      if (!response.ok) {
        throw new Error('download failed');
      }
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'security_events.log';
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Не удалось сохранить логи', error);
      setFeedback({
        severity: 'error',
        message: 'Не удалось сохранить файл логов.',
        anomalies: [],
      });
    }
  };

  return (
    <div className="dashboard-layout">
      <section className="hero-panel">
        <div className="hero-copy">
          <Typography component="p" className="eyebrow">
            Информационная безопасность
          </Typography>
          <Typography component="h1" className="hero-title">
            Выявление аномальной активности в логах
          </Typography>
          <Typography className="hero-text">
            Стенд показывает подозрительные входы ночью, серии неудачных
            авторизаций, признаки SQL-инъекций и автоматическую блокировку
            IP-адресов.
          </Typography>
        </div>

        <div className="stats-grid">
          <StatCard
            label="Всего событий"
            value={dashboard.summary.totalEvents}
            accent="neutral"
          />
          <StatCard
            label="Подозрительных"
            value={dashboard.summary.suspiciousEvents}
            accent="warning"
          />
          <StatCard
            label="Успешных входов"
            value={dashboard.summary.successfulLogins}
            accent="success"
          />
          <StatCard
            label="Активных блокировок"
            value={dashboard.summary.activeBlocks}
            accent="danger"
          />
        </div>

        <Paper className="panel-card chart-card" elevation={0}>
          <div className="panel-head">
            <div>
              <Typography variant="h6">Вспышки подозрительной активности</Typography>
              <Typography className="panel-subtitle">
                За последние 12 часов
              </Typography>
            </div>
          </div>
          <ActivityChart points={dashboard.chart} />
        </Paper>
      </section>

      <section className="workspace-panel">
        <Paper className="panel-card form-card" elevation={0}>
          <div className="panel-head">
            <div>
              <Typography variant="h6">Симулятор входа</Typography>
              <Typography className="panel-subtitle">
                Используй `admin / admin` для успешной авторизации
              </Typography>
            </div>
          </div>

          <Box component="form" className="auth-form" onSubmit={handleSubmit}>
            <TextField
              label="Логин"
              name="login"
              value={formData.login}
              onChange={handleChange}
              fullWidth
            />
            <TextField
              label="Пароль"
              name="password"
              type="password"
              value={formData.password}
              onChange={handleChange}
              fullWidth
            />
            <TextField
              label="IP-адрес"
              name="ip"
              value={formData.ip}
              onChange={handleChange}
              fullWidth
              helperText="Меняй IP, чтобы проверять обнаружение необычной активности"
            />
            <Button
              type="submit"
              variant="contained"
              size="large"
              disabled={loading}
            >
              {loading ? 'Проверка...' : 'Отправить событие'}
            </Button>
            <div className="action-row">
              <Button
                type="button"
                variant="outlined"
                color="error"
                onClick={handleClearHistory}
                disabled={loading}
              >
                Очистить историю
              </Button>
              <Button
                type="button"
                variant="outlined"
                onClick={handleDownloadLogs}
              >
                Сохранить логи
              </Button>
            </div>
          </Box>

          {feedback && (
            <Alert severity={feedback.severity} className="feedback-alert">
              <strong>{feedback.message}</strong>
              {feedback.anomalies.length > 0 && (
                <div className="alert-tags">
                  {feedback.anomalies.map((anomaly) => (
                    <Chip
                      key={anomaly}
                      size="small"
                      label={anomalyLabels[anomaly] ?? anomaly}
                    />
                  ))}
                </div>
              )}
            </Alert>
          )}
        </Paper>

        <div className="two-column-grid">
          <Paper className="panel-card" elevation={0}>
            <div className="panel-head">
              <div>
              <Typography variant="h6">Админ панель</Typography>
                <Typography className="panel-subtitle">
                  Последние сигналы о нарушениях
                </Typography>
              </div>
            </div>

            <Stack spacing={1.5}>
              {dashboard.alerts.length === 0 && (
                <Typography className="empty-state">
                  Пока подозрительных событий нет.
                </Typography>
              )}
              {dashboard.alerts.map((alert) => (
                <div key={`${alert.timestamp}-${alert.kind}`} className="event-row">
                  <div>
                    <Typography className="event-title">{alert.message}</Typography>
                    <Typography className="event-meta">
                      {alert.timestamp} | {alert.login || 'unknown'} | {alert.ip}
                    </Typography>
                  </div>
                  <Chip color="warning" size="small" label={anomalyLabels[alert.kind] ?? alert.kind} />
                </div>
              ))}
            </Stack>
          </Paper>

          <Paper className="panel-card" elevation={0}>
            <div className="panel-head">
              <div>
                <Typography variant="h6">Заблокированные IP</Typography>
                <Typography className="panel-subtitle">
                  Ограничение после частых неудачных попыток
                </Typography>
              </div>
            </div>

            <Stack spacing={1.5}>
              {dashboard.blockedIps.length === 0 && (
                <Typography className="empty-state">
                  Активных блокировок сейчас нет.
                </Typography>
              )}
              {dashboard.blockedIps.map((item) => (
                <div key={item.ip} className="event-row">
                  <div>
                    <Typography className="event-title">{item.ip}</Typography>
                    <Typography className="event-meta">
                      Блокировка до {item.blockedUntil}
                    </Typography>
                  </div>
                  <Chip color="error" size="small" label="Заблокирован" />
                </div>
              ))}
            </Stack>
          </Paper>
        </div>

        <Paper className="panel-card" elevation={0}>
          <div className="panel-head">
            <div>
              <Typography variant="h6">Журнал событий</Typography>
              <Typography className="panel-subtitle">
                Последние попытки входа и найденные аномалии
              </Typography>
            </div>
          </div>

          <div className="event-list">
            {dashboard.events.length === 0 && (
              <Typography className="empty-state">
                Событий пока нет. Отправь первую попытку входа.
              </Typography>
            )}
            {dashboard.events.map((event) => (
              <article
                key={`${event.timestamp}-${event.ip}-${event.status}`}
                className="event-card"
              >
                <div className="event-card-head">
                  <div>
                    <Typography className="event-title">
                      {event.login || 'unknown'} | {event.ip}
                    </Typography>
                    <Typography className="event-meta">
                      {event.timestamp} | статус: {event.status}
                    </Typography>
                  </div>
                  <div className="chip-row">
                    {event.anomalies.length === 0 ? (
                      <Chip size="small" color="success" label="Норма" />
                    ) : (
                      event.anomalies.map((anomaly) => (
                        <Chip
                          key={`${event.timestamp}-${anomaly}`}
                          size="small"
                          color="warning"
                          label={anomalyLabels[anomaly] ?? anomaly}
                        />
                      ))
                    )}
                  </div>
                </div>
                <Typography className="event-detail">{event.detail}</Typography>
              </article>
            ))}
          </div>
        </Paper>
      </section>
    </div>
  );
}

export default LoginForm;
