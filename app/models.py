from datetime import datetime
from app.extensions import db


class Controller(db.Model):
    __tablename__ = 'controllers'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=True)
    ssh_username = db.Column(db.String(100), nullable=False)
    ssh_password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    access_points = db.relationship('AccessPoint', back_populates='controller', cascade='all, delete-orphan', lazy=True)
    schedules = db.relationship('Schedule', back_populates='controller', lazy=True)

    def to_dict(self, include_credentials=False):
        data = {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'ssh_username': self.ssh_username,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'access_points_count': len(self.access_points) if self.access_points else 0
        }
        if include_credentials:
            data['ssh_password'] = self.ssh_password
        return data

    def __repr__(self):
        return f'<Controller {self.name}>'


class AccessPoint(db.Model):
    __tablename__ = 'access_points'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    controller_id = db.Column(db.Integer, db.ForeignKey('controllers.id'), nullable=False)
    status = db.Column(db.String(20), default='unknown', nullable=False)  # online, offline, unknown
    last_checked = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    controller = db.relationship('Controller', back_populates='access_points')
    reboot_logs = db.relationship(
        'RebootLog',
        back_populates='access_point',
        order_by='desc(RebootLog.executed_at)',
        cascade='all, delete-orphan',
        lazy=True
    )
    schedule_items = db.relationship('ScheduleAccessPoint', back_populates='access_point', cascade='all, delete-orphan', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'ip_address': self.ip_address,
            'controller_id': self.controller_id,
            'controller_name': self.controller.name if self.controller else None,
            'status': self.status,
            'last_checked': self.last_checked.isoformat() if self.last_checked else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def __repr__(self):
        return f'<AccessPoint {self.name} ({self.ip_address})>'


class Schedule(db.Model):
    __tablename__ = 'schedules'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    schedule_type = db.Column(db.String(20), nullable=False)  # daily, weekly, cron
    hour = db.Column(db.Integer, default=3, nullable=True)
    minute = db.Column(db.Integer, default=0, nullable=True)
    day_of_week = db.Column(db.String(50), nullable=True)  # e.g., 'mon,wed,fri'
    cron_expression = db.Column(db.String(100), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    controller_id = db.Column(db.Integer, db.ForeignKey('controllers.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    controller = db.relationship('Controller', back_populates='schedules')
    schedule_items = db.relationship('ScheduleAccessPoint', back_populates='schedule', cascade='all, delete-orphan', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'schedule_type': self.schedule_type,
            'hour': self.hour,
            'minute': self.minute,
            'day_of_week': self.day_of_week,
            'cron_expression': self.cron_expression,
            'is_active': self.is_active,
            'controller_id': self.controller_id,
            'controller_name': self.controller.name if self.controller else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'access_point_ids': [item.access_point_id for item in self.schedule_items] if self.schedule_items else []
        }

    def __repr__(self):
        return f'<Schedule {self.name} ({self.schedule_type})>'


class ScheduleAccessPoint(db.Model):
    __tablename__ = 'schedule_access_points'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    schedule_id = db.Column(db.Integer, db.ForeignKey('schedules.id'), nullable=False)
    access_point_id = db.Column(db.Integer, db.ForeignKey('access_points.id'), nullable=False)

    # Relationships
    schedule = db.relationship('Schedule', back_populates='schedule_items')
    access_point = db.relationship('AccessPoint', back_populates='schedule_items')

    __table_args__ = (
        db.UniqueConstraint('schedule_id', 'access_point_id', name='uq_schedule_access_point'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'schedule_id': self.schedule_id,
            'access_point_id': self.access_point_id,
            'access_point_name': self.access_point.name if self.access_point else None,
            'access_point_ip': self.access_point.ip_address if self.access_point else None
        }

    def __repr__(self):
        return f'<ScheduleAccessPoint Schedule:{self.schedule_id} AP:{self.access_point_id}>'


class RebootLog(db.Model):
    __tablename__ = 'reboot_logs'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    access_point_id = db.Column(db.Integer, db.ForeignKey('access_points.id'), nullable=False)
    schedule_id = db.Column(db.Integer, db.ForeignKey('schedules.id'), nullable=True)
    triggered_by = db.Column(db.String(20), nullable=False)  # manual, scheduled
    status = db.Column(db.String(20), nullable=False)  # success, failed, pending
    message = db.Column(db.Text, nullable=True)
    executed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    access_point = db.relationship('AccessPoint', back_populates='reboot_logs')
    schedule = db.relationship('Schedule', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'access_point_id': self.access_point_id,
            'access_point_name': self.access_point.name if self.access_point else None,
            'access_point_ip': self.access_point.ip_address if self.access_point else None,
            'schedule_id': self.schedule_id,
            'schedule_name': self.schedule.name if self.schedule else None,
            'triggered_by': self.triggered_by,
            'status': self.status,
            'message': self.message,
            'executed_at': self.executed_at.isoformat() if self.executed_at else None
        }

    def __repr__(self):
        return f'<RebootLog AP:{self.access_point_id} Status:{self.status} At:{self.executed_at}>'
