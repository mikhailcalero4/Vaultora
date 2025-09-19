#role hierarchies and delegation
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Role(db.Model):
    __tablename__ = "roles"
    id = db.Column(db.integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))
    parent_id = db.Column(db.Integer, db.ForeignKey("roles.id"))
    parent = db.relationship("Role", remote_side=[id])

    def includes(self, role_name):
        if self.name == role_name:
            return True
        if self.parent:
            return self.parent.includes(role_name)
        return False
    
class User(db.Model):
    __tablename__ = "users"
    id db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    #many to many supports delegation
    roles = db.relationship("Role", secondary="user_roles", backref="users")
    #track who delegated this role to whom
    delegated_from = db.Column(db.Integer, db.foreignKey("users.id"))
    delegated_by = db.relationship("User", remote_side=[id])

class UserRole(db.Model):
    __tablename__ = "user_roles"
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), primary_key=True)
    role_id = db.Column(db.Integer, db.foreignKey("roles.id"), primary_key=True)