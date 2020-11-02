package com.allweb.SpringSecurity.controller;

import com.allweb.SpringSecurity.model.StudentModel;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/student")
@CrossOrigin
public class StudentController {
    private static final List<StudentModel> STUDENT_MODELS = Arrays.asList(
      new StudentModel(1,"James Bond"),
      new StudentModel(2,"Maria Jones"),
      new StudentModel(3,"Anna Smith")
    );
    @GetMapping("/{studentId}")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN,ROLE_ADMINTRAINEE')")
    public StudentModel studentModel(@PathVariable("studentId") Integer studentId){
        return STUDENT_MODELS.stream()
                .filter(studentModel -> studentId.equals(studentModel.getStudentId()))
                .findFirst()
                .orElseThrow(()->new IllegalStateException("Student "+studentId+" does not exist"));
    }

}
