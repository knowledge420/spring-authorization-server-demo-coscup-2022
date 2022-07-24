package com.speaker.steven.web;

import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author Steven
 */
@RestController
@RequestMapping("/accounts")
public class AccountsController {

    private static String[] accounts = new String[]{"Account 1", "Account 2", "Account 3"};

    @GetMapping("")
    public String[] getAccounts() {
        return accounts;
    }

    @PostMapping("/{accountName}")
    public String[] createAccount(@PathVariable("accountName") String accountName) {
        List<String> accountList = new ArrayList<>(Arrays.asList(accounts));
        accountList.add(accountName);
        accounts = accountList.toArray(new String[accountList.size()]);
        return accounts;
    }
}