package com.allweb.SpringSecurity.controller;

import com.allweb.SpringSecurity.model.StudentModel;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/student")
public class StudentManagementController {
    private final List<StudentModel> STUDENTS = Arrays.asList(
            new StudentModel(1,"Dara"),
            new StudentModel(2,"Sokhour"),
            new StudentModel(3,"Pisey"),
            new StudentModel(4,"Daroth")
    );


    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN,ROLE_ADMINTRAINEE')")
    public List<StudentModel> getAllStudents(){
        return STUDENTS;
    }


    @PostMapping
    @PreAuthorize("hasAuthority('student:write')")
    public void registerNewStudent(@RequestBody StudentModel student){
        System.out.println(student);
    }


    @DeleteMapping("/{Id}")
    @PreAuthorize("hasAuthority('student:write')")
    public void deleteStudent(@PathVariable("Id") int studentId){
        System.out.println(studentId);
    }

    @PutMapping("/{Id}")
    @PreAuthorize("hasAuthority('student:write')")
    public void updateStudent(@PathVariable("Id") int studentId,@RequestBody StudentModel studentModel){
        System.out.printf("%s %s%n",studentId,studentModel);
    }

}
