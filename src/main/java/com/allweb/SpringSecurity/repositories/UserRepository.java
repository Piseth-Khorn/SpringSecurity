package com.allweb.SpringSecurity.repositories;

import com.allweb.SpringSecurity.model.UserModel;
import org.springframework.data.cassandra.repository.Query;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;
import org.springframework.data.cassandra.repository.CassandraRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends CassandraRepository<UserModel, UUID> {
    @Query("select name,password,role,email from user where name = ?0 allow filtering")
    Optional<UserModel> getUserModelByName(String name);

    @Query("select name,password,role,email from user where email = ?0 allow filtering")
    Optional<UserModel> getUserModelByEmail(String email);

    Boolean existsUserModelByEmail(String email);



}
