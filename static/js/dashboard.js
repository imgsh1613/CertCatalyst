// static/js/dashboard.js

// Modal functionality for student dashboard
document.addEventListener('DOMContentLoaded', function() {
    // Get the modal elements
    const modal = document.getElementById('uploadModal');
    if (!modal) return;
    
    const btn = document.getElementById('uploadCertBtn');
    const closeBtn = document.querySelector('.close');
    
    // Open modal when button is clicked
    btn.addEventListener('click', function() {
        modal.style.display = 'block';
    });
    
    // Close modal when X is clicked
    if (closeBtn) {
        closeBtn.addEventListener('click', function() {
            modal.style.display = 'none';
        });
    }
    
    // Close modal when clicking outside
    window.addEventListener('click', function(event) {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    });
    
    // Set default issue date to today
    const issueDateInput = document.getElementById('issue_date');
    if (issueDateInput) {
        const today = new Date().toISOString().split('T')[0];
        issueDateInput.value = today;
    }
    
    // File input validation
    const fileInput = document.getElementById('certificate_file');
    if (fileInput) {
        fileInput.addEventListener('change', function() {
            const filePath = this.value;
            const allowedExtensions = /(\.pdf|\.jpg|\.jpeg|\.png)$/i;
            
            if (!allowedExtensions.exec(filePath)) {
                alert('Please upload a valid file type: PDF, JPG or PNG');
                this.value = '';
                return false;
            }
        });
    }
    
    // Form validation before submission
    const uploadForm = document.querySelector('form[action*="upload_certificate"]');
    if (uploadForm) {
        uploadForm.addEventListener('submit', function(event) {
            const courseSelect = document.getElementById('course_id');
            const certNameInput = document.getElementById('certificate_name');
            
            if (courseSelect.value === '') {
                alert('Please select a course');
                event.preventDefault();
                return false;
            }
            
            if (certNameInput.value.trim() === '') {
                alert('Please enter a certificate name');
                event.preventDefault();
                return false;
            }
            
            if (!fileInput.files[0]) {
                alert('Please select a certificate file');
                event.preventDefault();
                return false;
            }
        });
    }
    
    // Add automatic timeout for alerts
    const alerts = document.querySelectorAll('.alert');
    if (alerts.length > 0) {
        setTimeout(function() {
            alerts.forEach(function(alert) {
                alert.style.opacity = '0';
                setTimeout(function() {
                    alert.style.display = 'none';
                }, 500);
            });
        }, 5000);
    }
});

// static/js/chart.min.js
// This would normally be a CDN import or local file for Chart.js, but for the purpose of this example,
// I'm providing a placeholder comment. In a real application, you would include the actual Chart.js library.
/* Chart.js v3.7.0 minimized library would go here */