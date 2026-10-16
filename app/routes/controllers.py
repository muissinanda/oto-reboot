"""
Controllers Route Blueprint for OTO REBOOT application.
Manages CRUD operations for UniFi Controllers, SSH credentials, and AP associations.
"""

import logging
from flask import Blueprint, render_template, request, flash, redirect, url_for

from app.extensions import db
from app.models import Controller, AccessPoint

logger = logging.getLogger(__name__)

controllers_bp = Blueprint('controllers', __name__, url_prefix='/controllers')


@controllers_bp.route('/', methods=['GET'])
def index():
    """
    List all controllers with the count of associated Access Points.
    Renders controllers.html.
    """
    try:
        controllers = Controller.query.order_by(Controller.name.asc()).all()

        # Compute AP count for each controller
        for ctrl in controllers:
            ctrl.ap_count = AccessPoint.query.filter_by(controller_id=ctrl.id).count()

        return render_template('controllers.html', controllers=controllers)

    except Exception as e:
        logger.error(f"Error listing controllers: {str(e)}", exc_info=True)
        flash(f'Gagal memuat data Controller: {str(e)}', 'danger')
        return render_template('controllers.html', controllers=[])


@controllers_bp.route('/add', methods=['POST'])
def add():
    """
    Add a new Controller.
    Form fields: name, description, ssh_username, ssh_password.
    Validates name uniqueness and required fields.
    """
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    ssh_username = request.form.get('ssh_username', '').strip()
    ssh_password = request.form.get('ssh_password', '').strip()

    if not name or not ssh_username or not ssh_password:
        flash('Nama Controller, Username SSH, dan Password SSH wajib diisi.', 'danger')
        return redirect(url_for('controllers.index'))

    # Validate name uniqueness
    existing_ctrl = Controller.query.filter_by(name=name).first()
    if existing_ctrl:
        flash(f'Controller dengan nama "{name}" sudah terdaftar.', 'danger')
        return redirect(url_for('controllers.index'))

    try:
        new_ctrl = Controller(
            name=name,
            description=description,
            ssh_username=ssh_username,
            ssh_password=ssh_password
        )
        db.session.add(new_ctrl)
        db.session.commit()
        flash(f'Controller "{name}" berhasil ditambahkan.', 'success')

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding controller: {str(e)}", exc_info=True)
        flash(f'Terjadi kesalahan saat menambahkan Controller: {str(e)}', 'danger')

    return redirect(url_for('controllers.index'))


@controllers_bp.route('/edit/<int:ctrl_id>', methods=['POST'])
def edit(ctrl_id):
    """
    Edit an existing Controller.
    Form fields: name, description, ssh_username, ssh_password.
    Validates name uniqueness (excluding self).
    """
    ctrl = Controller.query.get_or_404(ctrl_id)

    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    ssh_username = request.form.get('ssh_username', '').strip()
    ssh_password = request.form.get('ssh_password', '').strip()

    if not name or not ssh_username:
        flash('Nama Controller dan Username SSH wajib diisi.', 'danger')
        return redirect(url_for('controllers.index'))

    # Validate name uniqueness (excluding self)
    existing_ctrl = Controller.query.filter(
        Controller.name == name,
        Controller.id != ctrl_id
    ).first()
    if existing_ctrl:
        flash(f'Controller dengan nama "{name}" sudah digunakan.', 'danger')
        return redirect(url_for('controllers.index'))

    try:
        ctrl.name = name
        ctrl.description = description
        ctrl.ssh_username = ssh_username

        # Only update password if a new one was provided
        if ssh_password:
            ctrl.ssh_password = ssh_password

        db.session.commit()
        flash(f'Controller "{ctrl.name}" berhasil diperbarui.', 'success')

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating controller {ctrl_id}: {str(e)}", exc_info=True)
        flash(f'Gagal memperbarui Controller: {str(e)}', 'danger')

    return redirect(url_for('controllers.index'))


@controllers_bp.route('/delete/<int:ctrl_id>', methods=['POST'])
def delete(ctrl_id):
    """
    Delete a Controller.
    Fails with error if any Access Points are still associated with this controller.
    """
    ctrl = Controller.query.get_or_404(ctrl_id)
    ctrl_name = ctrl.name

    try:
        ap_count = AccessPoint.query.filter_by(controller_id=ctrl_id).count()
        if ap_count > 0:
            flash(
                f'Tidak dapat menghapus Controller "{ctrl_name}" karena masih memiliki {ap_count} '
                f'Access Point terkait. Silakan pindahkan atau hapus Access Point terlebih dahulu.',
                'danger'
            )
            return redirect(url_for('controllers.index'))

        db.session.delete(ctrl)
        db.session.commit()
        flash(f'Controller "{ctrl_name}" berhasil dihapus.', 'success')

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting controller {ctrl_id}: {str(e)}", exc_info=True)
        flash(f'Gagal menghapus Controller: {str(e)}', 'danger')

    return redirect(url_for('controllers.index'))
