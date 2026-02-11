/**
 * AdminDashboard.js
 * Main controller for the admin dashboard
 * Manages navigation between different sections and data loading
 */

class AdminDashboard {
  constructor() {
    this.currentSection = 'dashboard';
    this.currentPage = 1;
    this.itemsPerPage = 20;
    this.init();
  }

  init() {
    this.setupEventListeners();
    this.loadDashboard();
  }

  setupEventListeners() {
    // Navigation buttons
    document.querySelectorAll('[data-section]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const section = btn.getAttribute('data-section');
        this.switchSection(section);
      });
    });

    // Search functionality
    document.getElementById('globalSearch')?.addEventListener('input', (e) => {
      this.currentPage = 1;
      this.loadCurrentSection();
    });

    // Logout button
    document.getElementById('logoutBtn')?.addEventListener('click', () => {
      this.showLogoutModal();
    });
  }

  switchSection(section) {
    this.currentSection = section;
    this.currentPage = 1;

    // Update active nav
    document.querySelectorAll('[data-section]').forEach(btn => {
      btn.classList.remove('active');
    });
    document.querySelector(`[data-section="${section}"]`)?.classList.add('active');

    // Load section content
    this.loadCurrentSection();
  }

  loadCurrentSection() {
    const contentArea = document.getElementById('dashboardContent');
    contentArea.innerHTML = '<div class="loading">Loading...</div>';

    switch (this.currentSection) {
      case 'dashboard':
        this.loadDashboard();
        break;
      case 'orders':
        this.loadOrders();
        break;
      case 'files':
        this.loadFiles();
        break;
      case 'customers':
        this.loadCustomers();
        break;
      case 'transactions':
        this.loadTransactions();
        break;
      case 'analytics':
        this.loadAnalytics();
        break;
      default:
        this.loadDashboard();
    }
  }

  async loadDashboard() {
    try {
      const response = await fetch('/api/admin/stats');
      const data = await response.json();

      if (!data.success) throw new Error('Failed to load stats');

      const html = this.renderDashboardCards(data.stats);
      document.getElementById('dashboardContent').innerHTML = html;
    } catch (error) {
      console.error('Error loading dashboard:', error);
      document.getElementById('dashboardContent').innerHTML = 
        `<div class="error">Failed to load dashboard: ${error.message}</div>`;
    }
  }

  renderDashboardCards(stats) {
    return `
      <div class="section-header">
        <h1>Dashboard Overview</h1>
      </div>

      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-label">Total Orders</div>
          <div class="stat-value">${stats.totalOrders}</div>
          <div class="stat-trend ${stats.totalOrdersTrend < 0 ? 'negative' : ''}">
            ${stats.totalOrdersTrend >= 0 ? 'Up' : 'Down'} ${Math.abs(stats.totalOrdersTrend)}% from last week
          </div>
        </div>

        <div class="stat-card">
          <div class="stat-label">Successful Orders</div>
          <div class="stat-value">${stats.successfulOrders}</div>
          <div class="stat-trend">
            Up ${Math.abs(stats.successfulOrdersTrend)}% from last week
          </div>
        </div>

        <div class="stat-card">
          <div class="stat-label">Failed Orders</div>
          <div class="stat-value" style="color: #ff4757;">${stats.failedOrders}</div>
          <div class="stat-trend ${stats.failedOrdersTrend < 0 ? '' : 'negative'}">
            ${stats.failedOrdersTrend >= 0 ? 'Up' : 'Down'} ${Math.abs(stats.failedOrdersTrend)}% from last week
          </div>
        </div>

        <div class="stat-card">
          <div class="stat-label">Total Revenue</div>
          <div class="stat-value" style="color: #27ae60;">₹${stats.totalAmount.toFixed(2)}</div>
          <div class="stat-trend">
            Revenue tracking
          </div>
        </div>

        <div class="stat-card">
          <div class="stat-label">Unique Customers</div>
          <div class="stat-value">${stats.uniqueCustomers}</div>
          <div class="stat-trend">
            Total registered
          </div>
        </div>
      </div>
    `;
  }

  async loadOrders() {
    try {
      const search = document.getElementById('globalSearch')?.value || '';
      const status = document.getElementById('statusFilter')?.value || 'all';
      
      const response = await fetch(
        `/api/admin/orders?page=${this.currentPage}&limit=${this.itemsPerPage}&search=${search}&status=${status}`
      );
      const data = await response.json();

      if (!data.success) throw new Error('Failed to load orders');

      const html = this.renderOrdersTable(data.orders, data.pagination);
      document.getElementById('dashboardContent').innerHTML = html;
    } catch (error) {
      console.error('Error loading orders:', error);
      document.getElementById('dashboardContent').innerHTML = 
        `<div class="error">Failed to load orders: ${error.message}</div>`;
    }
  }

  renderOrdersTable(orders, pagination) {
    const rows = orders.map(order => `
      <tr>
        <td>${order.orderId}</td>
        <td>${new Date(order.dateTime).toLocaleString()}</td>
        <td>${order.customer}</td>
        <td>${order.transactionId}</td>
        <td>₹${order.total}</td>
        <td>
          <span class="badge ${order.status.toLowerCase().includes('success') ? 'badge-success' : 'badge-danger'}">
            ${order.status}
          </span>
        </td>
        <td>
          <button class="btn btn-sm btn-danger" onclick="dashboard.deleteOrder('${order._id}')">Delete</button>
        </td>
      </tr>
    `).join('');

    return `
      <div class="section-header">
        <h1>Orders Management</h1>
      </div>

      <div class="controls">
        <select onchange="dashboard.loadOrders()">
          <option value="all">All Status</option>
          <option value="successful">Successful</option>
          <option value="unsuccessful">Unsuccessful</option>
        </select>
      </div>

      <div class="section-container">
        <div class="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Order ID</th>
                <th>Date & Time</th>
                <th>Customer</th>
                <th>Transaction ID</th>
                <th>Total Amount</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              ${rows || '<tr><td colspan="7" style="text-align:center;">No orders found</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>

      <div class="pagination">
        ${this.renderPagination(pagination)}
      </div>
    `;
  }

  async loadFiles() {
    try {
      const search = document.getElementById('globalSearch')?.value || '';
      const response = await fetch(
        `/api/admin/files?page=${this.currentPage}&limit=${this.itemsPerPage}&search=${search}`
      );
      const data = await response.json();

      if (!data.success) throw new Error('Failed to load files');

      const html = this.renderFilesTable(data.files, data.pagination);
      document.getElementById('dashboardContent').innerHTML = html;
    } catch (error) {
      console.error('Error loading files:', error);
      document.getElementById('dashboardContent').innerHTML = 
        `<div class="error">Failed to load files: ${error.message}</div>`;
    }
  }

  renderFilesTable(files, pagination) {
    const rows = files.map(file => `
      <tr>
        <td>${file.filename}</td>
        <td>${file.user}</td>
        <td>${new Date(file.uploadedAt).toLocaleString()}</td>
        <td>₹${file.price || 0}</td>
        <td>
          <button class="btn btn-sm btn-secondary">Edit</button>
          <button class="btn btn-sm btn-danger" onclick="dashboard.deleteFile('${file._id}')">Delete</button>
        </td>
      </tr>
    `).join('');

    return `
      <div class="section-header">
        <h1>Files Management</h1>
      </div>

      <div class="section-container">
        <div class="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Filename</th>
                <th>Uploaded By</th>
                <th>Upload Date</th>
                <th>Price</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              ${rows || '<tr><td colspan="5" style="text-align:center;">No files found</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>

      <div class="pagination">
        ${this.renderPagination(pagination)}
      </div>
    `;
  }

  async loadCustomers() {
    try {
      const search = document.getElementById('globalSearch')?.value || '';
      const response = await fetch(
        `/api/admin/customers?page=${this.currentPage}&limit=${this.itemsPerPage}&search=${search}`
      );
      const data = await response.json();

      if (!data.success) throw new Error('Failed to load customers');

      const html = this.renderCustomersTable(data.customers, data.pagination);
      document.getElementById('dashboardContent').innerHTML = html;
    } catch (error) {
      console.error('Error loading customers:', error);
      document.getElementById('dashboardContent').innerHTML = 
        `<div class="error">Failed to load customers: ${error.message}</div>`;
    }
  }

  renderCustomersTable(customers, pagination) {
    const rows = customers.map(customer => `
      <tr>
        <td>${customer.full_address || 'N/A'}</td>
        <td>${customer.city || 'N/A'}</td>
        <td>${customer.region || 'N/A'}</td>
        <td>${customer.country || 'N/A'}</td>
        <td>${customer.postal_code || 'N/A'}</td>
      </tr>
    `).join('');

    return `
      <div class="section-header">
        <h1>Customers & Addresses</h1>
      </div>

      <div class="section-container">
        <div class="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Address</th>
                <th>City</th>
                <th>Region</th>
                <th>Country</th>
                <th>Postal Code</th>
              </tr>
            </thead>
            <tbody>
              ${rows || '<tr><td colspan="5" style="text-align:center;">No customers found</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>

      <div class="pagination">
        ${this.renderPagination(pagination)}
      </div>
    `;
  }

  async loadTransactions() {
    try {
      const response = await fetch(
        `/api/admin/transactions?page=${this.currentPage}&limit=${this.itemsPerPage}`
      );
      const data = await response.json();

      if (!data.success) throw new Error('Failed to load transactions');

      const html = this.renderTransactionsTable(data.transactions, data.pagination);
      document.getElementById('dashboardContent').innerHTML = html;
    } catch (error) {
      console.error('Error loading transactions:', error);
      document.getElementById('dashboardContent').innerHTML = 
        `<div class="error">Failed to load transactions: ${error.message}</div>`;
    }
  }

  renderTransactionsTable(transactions, pagination) {
    const rows = transactions.map(trans => `
      <tr>
        <td>${trans.transactionId || 'N/A'}</td>
        <td>${trans.userId || 'N/A'}</td>
        <td>₹${trans.amount || 0}</td>
        <td>${new Date(trans.createdAt).toLocaleString()}</td>
        <td>
          <span class="badge ${trans.status === 'success' ? 'badge-success' : 'badge-warning'}">
            ${trans.status}
          </span>
        </td>
      </tr>
    `).join('');

    return `
      <div class="section-header">
        <h1>Transactions</h1>
      </div>

      <div class="section-container">
        <div class="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Transaction ID</th>
                <th>User ID</th>
                <th>Amount</th>
                <th>Date & Time</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              ${rows || '<tr><td colspan="5" style="text-align:center;">No transactions found</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>

      <div class="pagination">
        ${this.renderPagination(pagination)}
      </div>
    `;
  }

  async loadAnalytics() {
    try {
      const response = await fetch('/api/admin/chart-data');
      const data = await response.json();

      if (!data.success) throw new Error('Failed to load analytics');

      const html = this.renderAnalytics(data);
      document.getElementById('dashboardContent').innerHTML = html;
    } catch (error) {
      console.error('Error loading analytics:', error);
      document.getElementById('dashboardContent').innerHTML = 
        `<div class="error">Failed to load analytics: ${error.message}</div>`;
    }
  }

  renderAnalytics(data) {
    return `
      <div class="section-header">
        <h1>Analytics & Reports</h1>
      </div>

      <div class="section-container">
        <h2>Monthly Revenue Trends</h2>
        <p style="color: #999; margin-bottom: 16px;">Data for the last 12 months</p>
        <pre style="background: #f5f7fa; padding: 16px; border-radius: 5px; overflow-x: auto; font-size: 12px;">${JSON.stringify(data.monthlyData, null, 2)}</pre>
      </div>

      <div class="section-container">
        <h2>Order Status Distribution</h2>
        <p style="color: #999; margin-bottom: 16px;">Current status breakdown</p>
        <pre style="background: #f5f7fa; padding: 16px; border-radius: 5px; overflow-x: auto; font-size: 12px;">${JSON.stringify(data.statusData, null, 2)}</pre>
      </div>
    `;
  }

  renderPagination(pagination) {
    const { page, pages } = pagination;
    let html = '';

    if (page > 1) {
      html += `<button onclick="dashboard.goToPage(${page - 1})">Previous</button>`;
    }

    for (let i = Math.max(1, page - 2); i <= Math.min(pages, page + 2); i++) {
      if (i === page) {
        html += `<button class="active">${i}</button>`;
      } else {
        html += `<button onclick="dashboard.goToPage(${i})">${i}</button>`;
      }
    }

    if (page < pages) {
      html += `<button onclick="dashboard.goToPage(${page + 1})">Next</button>`;
    }

    return html;
  }

  goToPage(page) {
    this.currentPage = page;
    this.loadCurrentSection();
  }

  async deleteOrder(orderId) {
    if (!confirm('Are you sure you want to delete this order?')) return;

    try {
      const response = await fetch(`/api/admin/orders/${orderId}`, {
        method: 'DELETE',
      });
      const data = await response.json();

      if (data.success) {
        this.loadOrders();
      } else {
        alert('Failed to delete order');
      }
    } catch (error) {
      console.error('Error deleting order:', error);
      alert('Failed to delete order');
    }
  }

  async deleteFile(fileId) {
    if (!confirm('Are you sure you want to delete this file?')) return;

    try {
      const response = await fetch(`/api/admin/files/${fileId}`, {
        method: 'DELETE',
      });
      const data = await response.json();

      if (data.success) {
        this.loadFiles();
      } else {
        alert('Failed to delete file');
      }
    } catch (error) {
      console.error('Error deleting file:', error);
      alert('Failed to delete file');
    }
  }

  showUploadModal() {
    // Will be implemented with modal system
    alert('Upload modal would open here');
  }

  showLogoutModal() {
    if (confirm('Are you sure you want to logout?')) {
      fetch('/logout', { method: 'GET' })
        .then(() => window.location.href = '/admin-login')
        .catch(err => console.error('Logout error:', err));
    }
  }
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  window.dashboard = new AdminDashboard();
});
