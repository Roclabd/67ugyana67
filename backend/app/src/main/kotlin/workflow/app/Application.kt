package workflow.app

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.scheduling.annotation.EnableScheduling
import workflow.engine.*

@SpringBootApplication(scanBasePackages = ["workflow"])
@EnableScheduling
class Application {
    @Bean fun nodeRegistry(nodes: List<NodeDefinition>) = NodeRegistry(nodes)
    @Bean fun graphValidator(nodes: NodeRegistry) = GraphValidator(nodes)
    @Bean fun executor(nodes: NodeRegistry, validator: GraphValidator, json: ObjectMapper) = DagExecutor(nodes, validator, json)
}

fun main(args: Array<String>) {
    runApplication<Application>(*args)
}
