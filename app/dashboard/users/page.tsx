"use client"

import { useEffect, useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Alert, AlertDescription } from "@/components/ui/alert"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Users, UserPlus, Search, Edit, Trash2, Shield, AlertTriangle, CheckCircle } from "lucide-react"

type User = {
  id: number;
  email: string;
  role: string;
  status: string;
  last_login: string | null;
  date_joined: string;
};

export default function UserManagementPage() {
  const [searchTerm, setSearchTerm] = useState("")
  const [filterRole, setFilterRole] = useState("all")
  const [filterStatus, setFilterStatus] = useState("all")
  const [isAddUserOpen, setIsAddUserOpen] = useState(false)
  const [isAddingUser, setIsAddingUser] = useState(false)
  const [addUserError, setAddUserError] = useState("")
  const [isDeletingUser, setIsDeletingUser] = useState(false)
  const [deleteUserError, setDeleteUserError] = useState("")
  const [userToDelete, setUserToDelete] = useState<User | null>(null)
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false)
  const [newUser, setNewUser] = useState({
    email: "",
    role: "viewer",
    password: "",
  });
  const [stats, setStats] = useState({
    total_users: 0,
    online_users: 0,
    pentesters: 0,
    admins: 0,
  });
  const [users, setUsers] = useState<User[]>([]);

  useEffect(() => {
    const fetchData = () => {
      console.log("Fetching user stats and list...");
      fetch("http://localhost:8000/api/user/stats/")
        .then((res) => {
          console.log("Stats response status:", res.status);
          return res.json();
        })
        .then((data) => {
          console.log("User stats data:", data);
          setStats(data);
        })
        .catch((error) => {
          console.error("Failed to fetch user stats:", error);
        });
      
      fetch("http://localhost:8000/api/user/list/")
        .then((res) => {
          console.log("User list response status:", res.status);
          return res.json();
        })
        .then((data) => {
          console.log("User list data:", data);
          console.log("🔍 Individual user statuses:");
          data.users.forEach((user: any) => {
            console.log(`  ${user.email}: status="${user.status}", is_logged_in=${user.is_logged_in}`);
          });
          setUsers(data.users);
        })
        .catch((error) => {
          console.error("Failed to fetch user list:", error);
        });
    };

    // Initial fetch
    fetchData();

    // Poll every 5 seconds to update user status
    const interval = setInterval(fetchData, 5000);

    return () => clearInterval(interval);
  }, []);

  const getRoleColor = (role: string) => {
    switch (role) {
      case "admin":
        return "bg-red-600"
      case "pentester":
        return "bg-blue-600"
      case "viewer":
        return "bg-green-600"
      case "guest":
        return "bg-gray-600"
      default:
        return "bg-gray-600"
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case "online":
        return "bg-green-600"
      case "offline":
        return "bg-gray-600"
      case "inactive":
        return "bg-red-600"
      case "suspended":
        return "bg-red-600"
      default:
        return "bg-gray-600"
    }
  }

  const filteredUsers = users.filter((user) => {
    const matchesSearch =
      user.email.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesRole = filterRole === "all" || user.role === filterRole
    const matchesStatus = filterStatus === "all" || user.status === filterStatus

    return matchesSearch && matchesRole && matchesStatus
  })

  const handleAddUser = async () => {
    // Clear previous errors
    setAddUserError("")
    
    // Validate input
    if (!newUser.email || !newUser.password) {
      setAddUserError("Email and password are required.");
      return;
    }
    
    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(newUser.email)) {
      setAddUserError("Please enter a valid email address.");
      return;
    }
    
    // Validate password length
    if (newUser.password.length < 6) {
      setAddUserError("Password must be at least 6 characters long.");
      return;
    }
    
    setIsAddingUser(true)
    
    try {
      const res = await fetch("http://localhost:8000/api/user/create/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: newUser.email,
          password: newUser.password,
          role: newUser.role,
        }),
      });
      
      const data = await res.json();
      
      if (data.success) {
        // Reset form and close dialog
        setIsAddUserOpen(false);
        setNewUser({ email: "", role: "viewer", password: "" });
        setAddUserError("")
        
        // Refresh user list and stats
        const fetchData = () => {
          fetch("http://localhost:8000/api/user/stats/")
            .then((res) => res.json())
            .then((data) => setStats(data))
            .catch((error) => console.error("Failed to fetch user stats:", error));
          
          fetch("http://localhost:8000/api/user/list/")
            .then((res) => res.json())
            .then((data) => setUsers(data.users))
            .catch((error) => console.error("Failed to fetch user list:", error));
        };
        
        fetchData()
        
        // Show success message (you could add a toast notification here)
        console.log("User created successfully:", data.user)
      } else {
        setAddUserError(data.error || "Failed to create user.");
      }
    } catch (error) {
      console.error("Error creating user:", error);
      setAddUserError("Network error. Please try again.");
    } finally {
      setIsAddingUser(false)
    }
  };

  const handleDeleteUser = async () => {
    if (!userToDelete) return;
    
    // Prevent deletion of admin account
    if (userToDelete.email === 'admin@pent.com') {
      setDeleteUserError("Cannot delete admin account.");
      return;
    }
    
    setIsDeletingUser(true);
    setDeleteUserError("");
    
    try {
      const res = await fetch("http://localhost:8000/api/user/delete/", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: userToDelete.email }),
      });
      
      const data = await res.json();
      
      if (data.success) {
        // Close dialog and reset
        setIsDeleteDialogOpen(false);
        setUserToDelete(null);
        setDeleteUserError("");
        
        // Refresh user list and stats
        const fetchData = () => {
          fetch("http://localhost:8000/api/user/stats/")
            .then((res) => res.json())
            .then((data) => setStats(data))
            .catch((error) => console.error("Failed to fetch user stats:", error));
          
          fetch("http://localhost:8000/api/user/list/")
            .then((res) => res.json())
            .then((data) => setUsers(data.users))
            .catch((error) => console.error("Failed to fetch user list:", error));
        };
        
        fetchData();
        console.log("User deleted successfully:", data.deleted_user);
      } else {
        setDeleteUserError(data.error || "Failed to delete user.");
      }
    } catch (error) {
      console.error("Error deleting user:", error);
      setDeleteUserError("Network error. Please try again.");
    } finally {
      setIsDeletingUser(false);
    }
  };

  const openDeleteDialog = (user: User) => {
    setUserToDelete(user);
    setDeleteUserError("");
    setIsDeleteDialogOpen(true);
  };

  return (
    <div className="space-y-4 sm:space-y-6">
      <div>
        <h1 className="text-2xl sm:text-3xl font-bold text-foreground mb-2">User Management</h1>
        <p className="text-muted-foreground text-sm sm:text-base">Manage user accounts, roles, and permissions</p>
      </div>

      {/* User Statistics */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-6">
        <Card className="bg-card border-border">
          <CardContent className="p-4 sm:p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-muted-foreground text-xs sm:text-sm">Total Users</p>
                <p className="text-xl sm:text-2xl font-bold text-foreground">{stats.total_users}</p>
              </div>
              <Users className="h-6 w-6 sm:h-8 sm:w-8 text-blue-400" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4 sm:p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-muted-foreground text-xs sm:text-sm">Online Users</p>
                <p className="text-xl sm:text-2xl font-bold text-foreground">{stats.online_users}</p>
              </div>
              <CheckCircle className="h-6 w-6 sm:h-8 sm:w-8 text-green-400" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4 sm:p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-muted-foreground text-xs sm:text-sm">Pentesters</p>
                <p className="text-xl sm:text-2xl font-bold text-foreground">{stats.pentesters}</p>
              </div>
              <Shield className="h-6 w-6 sm:h-8 sm:w-8 text-purple-400" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4 sm:p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-muted-foreground text-xs sm:text-sm">Admins</p>
                <p className="text-xl sm:text-2xl font-bold text-foreground">{stats.admins}</p>
              </div>
              <AlertTriangle className="h-6 w-6 sm:h-8 sm:w-8 text-red-400" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filters and Add User */}
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="text-foreground text-lg sm:text-xl">User Management</CardTitle>
          <CardDescription className="text-muted-foreground text-sm">Search, filter, and manage user accounts</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col sm:flex-row gap-3 sm:gap-4 mb-4">
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                <Input
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Search users..."
                  className="pl-10 bg-secondary border-border text-foreground text-sm sm:text-base"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 sm:flex gap-2 sm:gap-3">
              <Select value={filterRole} onValueChange={setFilterRole}>
                <SelectTrigger className="bg-secondary border-border text-foreground text-sm w-full sm:w-32">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-secondary border-border">
                  <SelectItem value="all">All Roles</SelectItem>
                  <SelectItem value="admin">Admin</SelectItem>
                  <SelectItem value="pentester">Pentester</SelectItem>
                  <SelectItem value="viewer">Viewer</SelectItem>
                  <SelectItem value="guest">Guest</SelectItem>
                </SelectContent>
              </Select>

              <Select value={filterStatus} onValueChange={setFilterStatus}>
                <SelectTrigger className="bg-secondary border-border text-foreground text-sm w-full sm:w-32">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-secondary border-border">
                  <SelectItem value="all">All Status</SelectItem>
                  <SelectItem value="online">Online</SelectItem>
                  <SelectItem value="offline">Offline</SelectItem>
                  <SelectItem value="inactive">Inactive</SelectItem>
                  <SelectItem value="suspended">Suspended</SelectItem>
                </SelectContent>
              </Select>

              <Dialog open={isAddUserOpen} onOpenChange={(open) => {
                setIsAddUserOpen(open)
                if (!open) {
                  // Reset form when dialog closes
                  setAddUserError("")
                  setNewUser({ email: "", role: "viewer", password: "" })
                }
              }}>
                <DialogTrigger asChild>
                  <Button className="bg-green-600 hover:bg-green-700 text-sm sm:col-span-2">
                    <UserPlus className="h-4 w-4 mr-2" />
                    <span className="hidden sm:inline">Add User</span>
                    <span className="sm:hidden">Add</span>
                  </Button>
                </DialogTrigger>
                <DialogContent className="bg-card border-border text-foreground">
                  <DialogHeader>
                    <DialogTitle>Add New User</DialogTitle>
                    <DialogDescription className="text-muted-foreground">
                      Create a new user account with appropriate permissions.
                    </DialogDescription>
                  </DialogHeader>
                  <div className="space-y-4">
                    {addUserError && (
                      <Alert className="bg-red-900 border-red-700">
                        <AlertDescription className="text-red-200">{addUserError}</AlertDescription>
                      </Alert>
                    )}
                    
                    <div className="space-y-2">
                      <Label htmlFor="email" className="text-foreground text-sm">
                        Email Address
                      </Label>
                      <Input
                        id="email"
                        type="email"
                        value={newUser.email}
                        onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                        className="bg-secondary border-border text-foreground"
                        placeholder="user@example.com"
                        disabled={isAddingUser}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="password" className="text-foreground text-sm">
                        Password
                      </Label>
                      <Input
                        id="password"
                        type="password"
                        value={newUser.password}
                        onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                        className="bg-secondary border-border text-foreground"
                        placeholder="Minimum 6 characters"
                        disabled={isAddingUser}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="role" className="text-foreground text-sm">
                        Role
                      </Label>
                      <Select 
                        value={newUser.role} 
                        onValueChange={(value) => setNewUser({ ...newUser, role: value })}
                        disabled={isAddingUser}
                      >
                        <SelectTrigger className="bg-secondary border-border text-foreground">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent className="bg-secondary border-border">
                          <SelectItem value="admin">Administrator</SelectItem>
                          <SelectItem value="pentester">Penetration Tester</SelectItem>
                          <SelectItem value="viewer">Viewer</SelectItem>
                          <SelectItem value="guest">Guest</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="flex flex-col sm:flex-row gap-2 pt-4">
                      <Button 
                        onClick={handleAddUser} 
                        className="bg-green-600 hover:bg-green-700"
                        disabled={isAddingUser}
                      >
                        {isAddingUser ? "Creating..." : "Create User"}
                      </Button>
                      <Button
                        variant="outline"
                        onClick={() => {
                          setIsAddUserOpen(false)
                          setAddUserError("")
                          setNewUser({ email: "", role: "viewer", password: "" })
                        }}
                        className="border-border text-foreground hover:bg-muted"
                        disabled={isAddingUser}
                      >
                        Cancel
                      </Button>
                    </div>
                  </div>
                </DialogContent>
              </Dialog>
              
              {/* Delete User Confirmation Dialog */}
              <Dialog open={isDeleteDialogOpen} onOpenChange={(open) => {
                setIsDeleteDialogOpen(open)
                if (!open) {
                  setUserToDelete(null)
                  setDeleteUserError("")
                }
              }}>
                <DialogContent className="bg-card border-border text-foreground">
                  <DialogHeader>
                    <DialogTitle>Delete User</DialogTitle>
                    <DialogDescription className="text-muted-foreground">
                      Are you sure you want to delete this user? This action cannot be undone.
                    </DialogDescription>
                  </DialogHeader>
                  <div className="space-y-4">
                    {deleteUserError && (
                      <Alert className="bg-red-900 border-red-700">
                        <AlertDescription className="text-red-200">{deleteUserError}</AlertDescription>
                      </Alert>
                    )}
                    
                    {userToDelete && (
                      <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
                        <div className="flex items-center space-x-3">
                          <div className="w-8 h-8 bg-red-600 rounded-full flex items-center justify-center">
                            <span className="text-white text-sm font-medium">
                              {userToDelete.email.charAt(0).toUpperCase()}
                            </span>
                          </div>
                          <div>
                            <p className="text-sm font-medium text-gray-900">{userToDelete.email}</p>
                            <p className="text-xs text-gray-500">Role: {userToDelete.role}</p>
                          </div>
                        </div>
                      </div>
                    )}
                    
                    <div className="flex flex-col sm:flex-row gap-2 pt-4">
                      <Button 
                        onClick={handleDeleteUser} 
                        className="bg-red-600 hover:bg-red-700"
                        disabled={isDeletingUser}
                      >
                        {isDeletingUser ? "Deleting..." : "Delete User"}
                      </Button>
                      <Button
                        variant="outline"
                        onClick={() => {
                          setIsDeleteDialogOpen(false)
                          setUserToDelete(null)
                          setDeleteUserError("")
                        }}
                        className="border-border text-foreground hover:bg-muted"
                        disabled={isDeletingUser}
                      >
                        Cancel
                      </Button>
                    </div>
                  </div>
                </DialogContent>
              </Dialog>
            </div>
          </div>

          {/* Users Table */}
          <div className="overflow-x-auto -mx-4 sm:mx-0">
            <div className="min-w-full inline-block align-middle">
              <Table>
                <TableHeader>
                  <TableRow className="border-border">
                    <TableHead className="text-foreground text-xs sm:text-sm whitespace-nowrap">User</TableHead>
                    <TableHead className="text-foreground text-xs sm:text-sm whitespace-nowrap">Role</TableHead>
                    <TableHead className="text-foreground text-xs sm:text-sm whitespace-nowrap">Status</TableHead>
                    <TableHead className="text-foreground text-xs sm:text-sm whitespace-nowrap">Last Login</TableHead>
                    <TableHead className="text-foreground text-xs sm:text-sm whitespace-nowrap">Login Count</TableHead>
                    <TableHead className="text-foreground text-xs sm:text-sm whitespace-nowrap">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredUsers.map((user) => (
                    <TableRow key={user.id} className="border-border hover:bg-muted">
                      <TableCell className="min-w-0">
                        <div className="flex items-center space-x-2 sm:space-x-3">
                          <div className="w-6 h-6 sm:w-8 sm:h-8 bg-purple-600 rounded-full flex items-center justify-center flex-shrink-0">
                            <span className="text-white text-xs sm:text-sm font-medium">
                              {user.email.charAt(0).toUpperCase()}
                            </span>
                          </div>
                          <div className="min-w-0">
                            <p className="text-foreground text-xs sm:text-sm font-medium truncate">
                              {user.email}
                            </p>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge className={`${getRoleColor(user.role)} text-xs`}>{user.role}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge className={`${getStatusColor(user.status)} text-xs`}>{user.status}</Badge>
                      </TableCell>
                      <TableCell className="text-foreground font-mono text-xs whitespace-nowrap">
                        {user.last_login ? user.last_login : "-"}
                      </TableCell>
                      <TableCell className="text-foreground text-xs sm:text-sm">{user.date_joined}</TableCell>
                      <TableCell className="text-foreground text-xs sm:text-sm">
                        <div className="flex items-center space-x-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => openDeleteDialog(user)}
                            disabled={user.email === 'admin@pent.com'}
                            className="h-6 px-2 text-xs border-red-600 text-red-600 hover:bg-red-600 hover:text-white"
                          >
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </div>

          <div className="mt-4 text-muted-foreground text-sm">
            Showing {filteredUsers.length} of {users.length} users
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
