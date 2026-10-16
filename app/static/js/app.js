/**
 * OTO REBOOT - Frontend Client JavaScript
 * Handles AJAX actions, dynamic modal population, toasts, auto-dismiss alerts,
 * schedule form conditionals, and bulk operations.
 */

document.addEventListener('DOMContentLoaded', function () {
    // 1. Auto-dismiss Flash Messages after 5 seconds
    initAutoDismissAlerts();

    // 2. Mobile Sidebar Toggle
    initSidebarToggle();

    // 3. Password Visibility Toggles
    initPasswordToggles();

    // 4. Select All Checkbox Handler (Bulk operations)
    initSelectAllCheckboxes();

    // 5. Schedule Form Dynamic Fields
    initScheduleForm();

    // 6. Edit Modals Data Population
    initEditModals();

    // 7. Delete Action Confirmation Hooks
    initDeleteConfirmations();

    // 8. Auto-refresh Dashboard Stats (if on dashboard)
    initDashboardAutoRefresh();
});

/**
 * Auto-dismiss Flash Messages
 */
function initAutoDismissAlerts() {
    const flashAlerts = document.querySelectorAll('.flash-message');
    flashAlerts.forEach(function (alert) {
        setTimeout(function () {
            alert.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
            alert.style.opacity = '0';
            alert.style.transform = 'translateY(-10px)';
            setTimeout(function () {
                if (alert.parentNode) {
                    alert.parentNode.removeChild(alert);
                }
            }, 500);
        }, 5000);
    });
}

/**
 * Mobile Sidebar Toggle & Backdrop
 */
function initSidebarToggle() {
    const toggleBtn = document.getElementById('sidebarToggleBtn');
    const sidebar = document.getElementById('sidebar');
    const backdrop = document.getElementById('sidebarBackdrop');

    if (toggleBtn && sidebar && backdrop) {
        toggleBtn.addEventListener('click', function () {
            sidebar.classList.toggle('open');
            backdrop.classList.toggle('active');
        });

        backdrop.addEventListener('click', function () {
            sidebar.classList.remove('open');
            backdrop.classList.remove('active');
        });
    }
}

/**
 * Toast Notification Helper
 * @param {string} message - Message text
 * @param {string} type - 'success', 'error', 'info', or 'warning'
 */
function showToast(message, type = 'info') {
    let container = document.getElementById('toastContainer');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toastContainer';
        container.className = 'toast-container-custom';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    const typeClass = type === 'success' ? 'toast-success' : (type === 'danger' || type === 'error' ? 'toast-error' : 'toast-info');
    toast.className = `custom-toast ${typeClass}`;

    let iconClass = 'fa-info-circle text-info';
    if (type === 'success') iconClass = 'fa-check-circle text-success';
    if (type === 'error' || type === 'danger') iconClass = 'fa-exclamation-circle text-danger';
    if (type === 'warning') iconClass = 'fa-triangle-exclamation text-warning';

    toast.innerHTML = `
        <i class="fas ${iconClass}"></i>
        <div class="flex-grow-1" style="font-size: 0.88rem;">${escapeHtml(message)}</div>
        <button type="button" class="btn-close btn-close-white ms-2" style="font-size: 0.7rem;" aria-label="Close"></button>
    `;

    container.appendChild(toast);

    toast.querySelector('.btn-close').addEventListener('click', function () {
        removeToast(toast);
    });

    setTimeout(function () {
        removeToast(toast);
    }, 4500);
}

function removeToast(toast) {
    if (!toast || !toast.parentNode) return;
    toast.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(15px)';
    setTimeout(function () {
        if (toast.parentNode) {
            toast.parentNode.removeChild(toast);
        }
    }, 400);
}

function escapeHtml(text) {
    if (!text) return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

/**
 * Toggle Password Visibility
 */
function initPasswordToggles() {
    document.querySelectorAll('.password-toggle-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
            const targetId = this.getAttribute('data-target');
            const input = document.getElementById(targetId);
            if (!input) return;

            const icon = this.querySelector('i');
            if (input.type === 'password') {
                input.type = 'text';
                if (icon) {
                    icon.classList.remove('fa-eye');
                    icon.classList.add('fa-eye-slash');
                }
            } else {
                input.type = 'password';
                if (icon) {
                    icon.classList.remove('fa-eye-slash');
                    icon.classList.add('fa-eye');
                }
            }
        });
    });
}

/**
 * Checkboxes & Bulk Operations
 */
function initSelectAllCheckboxes() {
    // Access Points table master checkbox
    const selectAllAp = document.getElementById('selectAllAps');
    if (selectAllAp) {
        selectAllAp.addEventListener('change', function () {
            const isChecked = this.checked;
            document.querySelectorAll('.ap-checkbox').forEach(function (cb) {
                cb.checked = isChecked;
            });
            updateBulkActionBar();
        });

        document.querySelectorAll('.ap-checkbox').forEach(function (cb) {
            cb.addEventListener('change', function () {
                const all = document.querySelectorAll('.ap-checkbox');
                const checked = document.querySelectorAll('.ap-checkbox:checked');
                if (selectAllAp) {
                    selectAllAp.checked = (all.length > 0 && all.length === checked.length);
                    selectAllAp.indeterminate = (checked.length > 0 && checked.length < all.length);
                }
                updateBulkActionBar();
            });
        });
    }

    // Schedule form: Select All per Controller group
    document.querySelectorAll('.group-select-all').forEach(function (groupCheckbox) {
        groupCheckbox.addEventListener('change', function () {
            const groupName = this.getAttribute('data-group');
            const isChecked = this.checked;
            document.querySelectorAll(`.schedule-ap-item[data-group="${groupName}"]`).forEach(function (item) {
                item.checked = isChecked;
            });
        });
    });
}

function updateBulkActionBar() {
    const checked = document.querySelectorAll('.ap-checkbox:checked');
    const bulkBar = document.getElementById('bulkActionBar');
    const bulkCount = document.getElementById('bulkSelectedCount');

    if (bulkBar) {
        if (checked.length > 0) {
            bulkBar.classList.remove('d-none');
            if (bulkCount) bulkCount.textContent = checked.length;
        } else {
            bulkBar.classList.add('d-none');
            if (bulkCount) bulkCount.textContent = '0';
        }
    }
}

/**
 * Schedule Form Conditional Fields
 */
function initScheduleForm() {
    const scheduleTypeInputs = document.querySelectorAll('input[name="schedule_type"]');
    if (!scheduleTypeInputs || scheduleTypeInputs.length === 0) return;

    function updateFields(selectedType) {
        const dailyFields = document.getElementById('dailyFields');
        const weeklyFields = document.getElementById('weeklyFields');
        const cronFields = document.getElementById('cronFields');

        if (dailyFields) dailyFields.classList.add('d-none');
        if (weeklyFields) weeklyFields.classList.add('d-none');
        if (cronFields) cronFields.classList.add('d-none');

        if (selectedType === 'daily') {
            if (dailyFields) dailyFields.classList.remove('d-none');
        } else if (selectedType === 'weekly') {
            if (weeklyFields) weeklyFields.classList.remove('d-none');
        } else if (selectedType === 'cron') {
            if (cronFields) cronFields.classList.remove('d-none');
        }
    }

    scheduleTypeInputs.forEach(function (input) {
        input.addEventListener('change', function () {
            if (this.checked) {
                updateFields(this.value);
            }
        });
        if (input.checked) {
            updateFields(input.value);
        }
    });
}

/**
 * Edit Modals Data Population
 */
function initEditModals() {
    // Edit Access Point Modal
    const editApModal = document.getElementById('editApModal');
    if (editApModal) {
        editApModal.addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget;
            if (!button) return;

            const id = button.getAttribute('data-id');
            const name = button.getAttribute('data-name');
            const ip = button.getAttribute('data-ip');
            const controllerId = button.getAttribute('data-controller-id');

            const form = editApModal.querySelector('form');
            if (form && id) {
                form.action = `/access-points/edit/${id}`;
            }

            const nameInput = editApModal.querySelector('#editApName');
            const ipInput = editApModal.querySelector('#editApIp');
            const controllerSelect = editApModal.querySelector('#editApController');

            if (nameInput) nameInput.value = name || '';
            if (ipInput) ipInput.value = ip || '';
            if (controllerSelect && controllerId) controllerSelect.value = controllerId;
        });
    }

    // Edit Controller Modal
    const editControllerModal = document.getElementById('editControllerModal');
    if (editControllerModal) {
        editControllerModal.addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget;
            if (!button) return;

            const id = button.getAttribute('data-id');
            const name = button.getAttribute('data-name');
            const description = button.getAttribute('data-description');
            const sshUsername = button.getAttribute('data-ssh-username');

            const form = editControllerModal.querySelector('form');
            if (form && id) {
                form.action = `/controllers/edit/${id}`;
            }

            const nameInput = editControllerModal.querySelector('#editCtrlName');
            const descInput = editControllerModal.querySelector('#editCtrlDesc');
            const sshUserInput = editControllerModal.querySelector('#editCtrlSshUser');
            const sshPassInput = editControllerModal.querySelector('#editCtrlSshPass');

            if (nameInput) nameInput.value = name || '';
            if (descInput) descInput.value = description || '';
            if (sshUserInput) sshUserInput.value = sshUsername || '';
            if (sshPassInput) sshPassInput.value = ''; // clear password field
        });
    }
}

/**
 * Generic Confirm Dialogs for Delete / Destructive Actions
 */
function initDeleteConfirmations() {
    document.querySelectorAll('[data-confirm]').forEach(function (element) {
        element.addEventListener('click', function (e) {
            const message = this.getAttribute('data-confirm') || 'Apakah Anda yakin ingin melakukan tindakan ini?';
            if (!confirm(message)) {
                e.preventDefault();
                return false;
            }
        });
    });
}

/**
 * AJAX: Reboot Single AP
 * @param {number|string} apId
 * @param {HTMLElement} btnElement
 */
function rebootAp(apId, btnElement = null) {
    if (!apId) return;

    if (!confirm('Apakah Anda yakin ingin mereboot Access Point ini?')) {
        return;
    }

    let originalHtml = '';
    if (btnElement) {
        originalHtml = btnElement.innerHTML;
        btnElement.disabled = true;
        btnElement.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status" aria-hidden="true"></span> Rebooting...';
    }

    fetch(`/api/reboot-ap/${apId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json().then(data => ({ status: response.status, body: data })))
    .then(({ status, body }) => {
        if (body.success) {
            showToast(body.message || 'Perintah reboot berhasil dikirim.', 'success');
        } else {
            showToast(body.message || 'Gagal mereboot Access Point.', 'error');
        }
    })
    .catch(err => {
        console.error('Reboot error:', err);
        showToast('Terjadi kesalahan jaringan saat mereboot AP.', 'error');
    })
    .finally(() => {
        if (btnElement) {
            btnElement.disabled = false;
            btnElement.innerHTML = originalHtml;
        }
    });
}

/**
 * AJAX: Check AP Status
 * @param {number|string} apId
 * @param {HTMLElement} btnElement
 */
function checkApStatus(apId, btnElement = null) {
    if (!apId) return;

    let originalHtml = '';
    if (btnElement) {
        originalHtml = btnElement.innerHTML;
        btnElement.disabled = true;
        btnElement.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
    }

    fetch(`/api/check-ap/${apId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast(data.message || `Status AP diperbarui: ${data.status}`, 'success');
            // Update badge in table if present
            const badge = document.querySelector(`.status-badge-ap-${apId}`);
            if (badge) {
                const status = (data.status || 'unknown').toLowerCase();
                badge.className = `status-badge ${status} status-badge-ap-${apId}`;
                badge.innerHTML = `<span class="dot"></span> ${status}`;
            }

            // Update Last Checked cell if present
            const lastCheckedCell = document.querySelector(`.last-checked-ap-${apId}`);
            if (lastCheckedCell) {
                const now = new Date();
                lastCheckedCell.textContent = now.toLocaleDateString('id-ID', {
                    day: '2-digit', month: 'short', year: 'numeric',
                    hour: '2-digit', minute: '2-digit', second: '2-digit'
                });
            }
        } else {
            showToast(data.message || 'Gagal memeriksa status AP.', 'error');
        }
    })
    .catch(err => {
        console.error('Check status error:', err);
        showToast('Gagal memeriksa status AP via jaringan.', 'error');
    })
    .finally(() => {
        if (btnElement) {
            btnElement.disabled = false;
            btnElement.innerHTML = originalHtml;
        }
    });
}

/**
 * AJAX: Check All APs Status
 * @param {HTMLElement} btnElement
 */
function checkAllAps(btnElement = null) {
    let originalHtml = '';
    if (btnElement) {
        originalHtml = btnElement.innerHTML;
        btnElement.disabled = true;
        btnElement.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status" aria-hidden="true"></span> Memeriksa...';
    }

    fetch('/api/check-all', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast(data.message || 'Pemeriksaan status seluruh AP selesai.', 'success');
            // If data contains individual AP status results, update DOM
            if (Array.isArray(data.data)) {
                data.data.forEach(item => {
                    const badge = document.querySelector(`.status-badge-ap-${item.id}`);
                    if (badge) {
                        const status = (item.status || 'unknown').toLowerCase();
                        badge.className = `status-badge ${status} status-badge-ap-${item.id}`;
                        badge.innerHTML = `<span class="dot"></span> ${status}`;
                    }
                });
            } else {
                // Refresh dashboard counters
                refreshStats();
            }
        } else {
            showToast(data.message || 'Gagal memeriksa status AP massal.', 'error');
        }
    })
    .catch(err => {
        console.error('Check all error:', err);
        showToast('Terjadi kesalahan saat memeriksa semua AP.', 'error');
    })
    .finally(() => {
        if (btnElement) {
            btnElement.disabled = false;
            btnElement.innerHTML = originalHtml;
        }
    });
}

/**
 * AJAX: Refresh Dashboard Stats Counters
 */
function refreshStats() {
    fetch('/api/stats')
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            const totalAps = document.getElementById('statTotalAps');
            const onlineAps = document.getElementById('statOnlineAps');
            const offlineAps = document.getElementById('statOfflineAps');
            const activeScheds = document.getElementById('statActiveSchedules');

            if (totalAps) totalAps.textContent = data.total_aps;
            if (onlineAps) onlineAps.textContent = data.online;
            if (offlineAps) offlineAps.textContent = data.offline;
            if (activeScheds) activeScheds.textContent = data.active_schedules;
        }
    })
    .catch(err => console.debug('Stats refresh background poll error:', err));
}

/**
 * Auto-refresh dashboard stats every 60 seconds
 */
function initDashboardAutoRefresh() {
    const isDashboard = document.getElementById('statTotalAps');
    if (isDashboard) {
        setInterval(refreshStats, 60000);
    }
}
