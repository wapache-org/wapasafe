package org.wapache.security.oauth2.server.demo.web.controller;

import org.wapache.security.oauth2.server.demo.entity.Client;
import org.wapache.security.oauth2.server.demo.entity.Status;
import org.wapache.security.oauth2.server.demo.service.ClientService;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1")
@Tag(name = "Client")
public class ClientController {

    @Autowired
    private ClientService clientService;

    @GetMapping("/clients")
    public List<Client> list() {
        return clientService.findAll();
    }

    @PostMapping(value = "/clients/create")
    public Client create(Client client) {
        return clientService.createClient(client);
    }

    @PostMapping(value = "/clients/{id}/update")
    public Client update(Client client) {
        return clientService.updateClient(client);
    }

    @DeleteMapping(value = "/clients/{id}/delete")
    public Status delete(@PathVariable("id") Long id) {
        clientService.deleteClient(id);
        Status status = new Status();
        status.setCode(200);
        status.setMsg("删除成功");
        return status;
    }

}
