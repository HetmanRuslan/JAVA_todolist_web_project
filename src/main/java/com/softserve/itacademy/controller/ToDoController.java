package com.softserve.itacademy.controller;

import com.softserve.itacademy.model.Task;
import com.softserve.itacademy.model.ToDo;
import com.softserve.itacademy.model.User;
import com.softserve.itacademy.repository.UserRepository;
import com.softserve.itacademy.service.TaskService;
import com.softserve.itacademy.service.ToDoService;
import com.softserve.itacademy.service.UserService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/todos")
public class ToDoController {

    private final ToDoService todoService;
    private final TaskService taskService;
    private final UserService userService;
    private final UserRepository userRepository;

    public ToDoController(ToDoService todoService, TaskService taskService, UserService userService, UserRepository userRepository) {
        this.todoService = todoService;
        this.taskService = taskService;
        this.userService = userService;
        this.userRepository = userRepository;
    }

    @GetMapping("/create/users/{owner_id}")
    public String create(@PathVariable("owner_id") long ownerId, Model model, Principal principal) {
        User user = userRepository.findByEmail(principal.getName());
        if (userService.readById(ownerId).getEmail().equals(principal.getName()) || user.getRole().getName().equals("ADMIN")) {
            model.addAttribute("todo", new ToDo());
            model.addAttribute("ownerId", ownerId);
            return "create-todo";
        }
        return "redirect:/access-denied";
    }

    @PostMapping("/create/users/{owner_id}")
    public String create(@PathVariable("owner_id") long ownerId, @Validated @ModelAttribute("todo") ToDo todo, BindingResult result) {
        if (result.hasErrors()) {
            return "create-todo";
        }
        todo.setCreatedAt(LocalDateTime.now());
        todo.setOwner(userService.readById(ownerId));
        todoService.create(todo);
        return "redirect:/todos/all/users/" + ownerId;
    }

    @GetMapping("/{id}/tasks")
    public String read(@PathVariable long id, Model model, Principal principal) {
        User user = userRepository.findByEmail(principal.getName());
        if (todoService.readById(id).getOwner().getEmail().equals(principal.getName()) || user.getRole().getName().equals("ADMIN")) {
            ToDo todo = todoService.readById(id);
            List<Task> tasks = taskService.getByTodoId(id);
            List<User> users = userService.getAll().stream()
                    .filter(u -> u.getId() != todo.getOwner().getId()).collect(Collectors.toList());
            model.addAttribute("todo", todo);
            model.addAttribute("tasks", tasks);
            model.addAttribute("users", users);
            return "todo-tasks";
        }
        return "redirect:/access-denied";
    }

    @GetMapping("/{todo_id}/update/users/{owner_id}")
    public String update(@PathVariable("todo_id") long todoId, @PathVariable("owner_id") long ownerId, Model model, Principal principal) {
        User user = userRepository.findByEmail(principal.getName());
        if (userService.readById(ownerId).getEmail().equals(principal.getName()) || user.getRole().getName().equals("ADMIN")) {
            ToDo todo = todoService.readById(todoId);
            model.addAttribute("todo", todo);
            return "update-todo";
        }
        return "redirect:/access-denied";
    }

    @PostMapping("/{todo_id}/update/users/{owner_id}")
    public String update(@PathVariable("todo_id") long todoId, @PathVariable("owner_id") long ownerId,
                         @Validated @ModelAttribute("todo") ToDo todo, BindingResult result) {
        if (result.hasErrors()) {
            todo.setOwner(userService.readById(ownerId));
            return "update-todo";
        }
        ToDo oldTodo = todoService.readById(todoId);
        todo.setOwner(oldTodo.getOwner());
        todo.setCollaborators(oldTodo.getCollaborators());
        todoService.update(todo);
        return "redirect:/todos/all/users/" + ownerId;
    }

    @GetMapping("/{todo_id}/delete/users/{owner_id}")
    public String delete(@PathVariable("todo_id") long todoId, @PathVariable("owner_id") long ownerId, Principal principal) {
        User user = userRepository.findByEmail(principal.getName());
        if (userService.readById(ownerId).getEmail().equals(principal.getName()) || user.getRole().getName().equals("ADMIN")) {
            todoService.delete(todoId);
            return "redirect:/todos/all/users/" + ownerId;
        }
        return "redirect:/access-denied";
    }

    @GetMapping("/all/users/{user_id}")
    public String getAll(@PathVariable("user_id") long userId, Model model, Principal principal) {
        User user = userRepository.findByEmail(principal.getName());
        if (userService.readById(userId).getEmail().equals(principal.getName()) || user.getRole().getName().equals("ADMIN")) {
            List<ToDo> todos = todoService.getByUserId(userId);
            model.addAttribute("todos", todos);
            model.addAttribute("user", userService.readById(userId));
            return "todos-user";
        }
        return "redirect:/access-denied";
    }

    @GetMapping("/{id}/add")
    public String addCollaborator(@PathVariable long id, @RequestParam("user_id") long userId) {
        ToDo todo = todoService.readById(id);
        List<User> collaborators = todo.getCollaborators();
        collaborators.add(userService.readById(userId));
        todo.setCollaborators(collaborators);
        todoService.update(todo);
        return "redirect:/todos/" + id + "/tasks";
    }

    @GetMapping("/{id}/remove")
    public String removeCollaborator(@PathVariable long id, @RequestParam("user_id") long userId) {
        ToDo todo = todoService.readById(id);
        List<User> collaborators = todo.getCollaborators();
        collaborators.remove(userService.readById(userId));
        todo.setCollaborators(collaborators);
        todoService.update(todo);
        return "redirect:/todos/" + id + "/tasks";
    }
}
