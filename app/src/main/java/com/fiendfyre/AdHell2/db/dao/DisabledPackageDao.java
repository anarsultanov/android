package com.fiendfyre.AdHell2.db.dao;

import android.arch.persistence.room.Dao;
import android.arch.persistence.room.Insert;
import android.arch.persistence.room.Query;
import android.arch.persistence.room.TypeConverters;

import com.fiendfyre.AdHell2.db.DateConverter;
import com.fiendfyre.AdHell2.db.entity.DisabledPackage;

import java.util.List;

@Dao
@TypeConverters(DateConverter.class)
public interface DisabledPackageDao {

    @Query("SELECT * FROM DisabledPackage")
    List<DisabledPackage> getAll();

    @Insert
    void insertAll(List<DisabledPackage> disabledPackages);
}
