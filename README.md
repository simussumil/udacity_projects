# Item Catalog Project.


This is a web application that displays list of categories and itmes in it.
A user can register with thrid party services sucn as facebook or gmail. 
Authenticated user can creat, delete, edit and update items.
Also, this project provide JSON endpoints.


## Skill used in this project
SQLAlchemy, Bootstrap, Flask, HTML, CSS, OAuth, Python


## How to run

1. Install Vagrant and VirtualBox
2. Clone the fullstack-nanodegree-vm
3. Launch the Vagrant VM (vagrant up)
4. run model.py to create catalog.db(python /vagrant/catalog/model.py)
4. Run the application within the VM (python /vagrant/catalog/application.py)
5. Access and test application by visiting http://localhost:8000 locally


## JSON Endpoints

categoryJSON: /category/<int:category_id>/item/JSON' - Displays items for a specific category

categoryItemJSON: /category/<int:category_id>/item/<int:item_id>/JSON - Displays a specific item in the category

categoriesJSON: /category/JSON -Displays all categories

