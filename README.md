**Product Management System**

The Product Management System is a web-based application built with Flask to efficiently manage product inventories. It provides essential CRUD operations—Create, Read, Update, and Delete—for handling product records. The application uses SQLite for data storage, HTML/CSS with Bootstrap for responsive UI, and Jinja2 templating for dynamic content rendering.

A key feature of this system is the integration of Razorpay, a popular Indian payment gateway. This allows users to simulate real-time payments for any product listed in the system. When a user clicks the "Buy" or "Pay" button, a Razorpay Checkout popup is triggered, showing product details and enabling payment via multiple options like card, UPI, or net banking.

The integration uses the Razorpay Python SDK to create orders and generate payment sessions. The client-side JavaScript then handles the Razorpay widget and callback on successful payment. This gives the application real-world capabilities for handling transactions and introduces users to secure payment workflows.

This project not only demonstrates backend logic and frontend design but also showcases third-party API integration. It’s ideal for learning or demonstrating full-stack web development using Python and can be extended with features like authentication, product search, or order history.

## Read the Flask Document .

**Before running these are file need to install**
  ~pip install flask flask-bcrypt flask-sqlalchemy flask-login flask-wtf authlib razorpay requests

**run the file:**
 python app.py
